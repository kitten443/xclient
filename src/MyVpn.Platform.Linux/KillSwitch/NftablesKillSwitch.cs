using System.Runtime.InteropServices;
using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.KillSwitch;
using MyVpn.Platform.Linux.Execution;

namespace MyVpn.Platform.Linux.KillSwitch;

/// <summary>
/// Applies the Kill Switch through nftables.
/// </summary>
/// <remarks>
/// <para>
/// The rule set itself is produced by <see cref="NftablesKillSwitchRenderer"/>, which is a pure
/// function and is verified separately by installing its output into a throwaway kernel network
/// namespace. This class does only three things: check that it may act, hand the rendered file to
/// <c>nft</c>, and read back what the kernel actually holds.
/// </para>
/// <para>
/// <b>Reading back matters.</b> Trusting the exit code of a firewall command is how a client ends
/// up reporting "protected" while the rules were silently dropped — an <c>nft</c> invocation can
/// succeed against a different netns, or another tool can flush the table immediately afterwards.
/// Every apply is followed by an inspection performed by the caller, and
/// <see cref="InspectAsync"/> is what answers it.
/// </para>
/// </remarks>
public sealed class NftablesKillSwitch : IKillSwitch
{
    /// <summary>Marker present in every generated rule set, used to recognise our own table.</summary>
    private const string OwnershipMarker = "myvpn: default deny";

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;

    public NftablesKillSwitch(ICommandRunner? runner = null, Func<bool>? isElevated = null)
    {
        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? DefaultElevationCheck;
    }

    public string MechanismName => "nftables";

    /// <summary>
    /// True when the tool is present <i>and</i> this process may use it.
    /// </summary>
    /// <remarks>
    /// Reporting <c>true</c> without privileges would make the session believe it is protected and
    /// then fail at the last moment, after the config was staged. The honest answer here is what
    /// lets the connect flow decide before touching anything.
    /// </remarks>
    public bool IsSupported => _runner.Exists("nft") && _isElevated();

    public async Task<KillSwitchApplyResult> ApplyAsync(KillSwitchPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        if (plan.Mode == KillSwitchMode.Disabled)
        {
            return await RemoveAsync(plan.Identifier, cancellationToken).ConfigureAwait(false);
        }

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return KillSwitchApplyResult.Failed(validation.Error!);
        }

        if (!_runner.Exists("nft"))
        {
            return KillSwitchApplyResult.Failed(new MyVpnError(
                ErrorCodes.PlatformToolMissing,
                "error.platform.tool_missing",
                ErrorSeverity.Error,
                "The 'nft' tool is not installed, so the Kill Switch cannot be applied.",
                "killswitch.install_nftables")
                .WithArg("tool", "nft"));
        }

        if (!_isElevated())
        {
            return KillSwitchApplyResult.Failed(NotElevated());
        }

        var ruleset = NftablesKillSwitchRenderer.RenderInstall(plan);
        var applied = await RunRulesetAsync(ruleset, cancellationToken).ConfigureAwait(false);

        return applied.Succeeded
            ? KillSwitchApplyResult.Ok(applied.Combined)
            : KillSwitchApplyResult.Failed(ApplyFailed(applied.Combined), applied.Combined);
    }

    public async Task<KillSwitchApplyResult> RemoveAsync(string identifier, CancellationToken cancellationToken)
    {
        if (!_runner.Exists("nft"))
        {
            // Nothing to remove, and reporting failure would leave the session unable to reach a
            // clean state. The teardown script is idempotent, so this is genuinely "already done".
            return KillSwitchApplyResult.Ok("nft is not installed; nothing to remove.");
        }

        if (!_isElevated())
        {
            return KillSwitchApplyResult.Failed(NotElevated());
        }

        // Idempotent by construction: the script creates the table if missing and then deletes it.
        var removed = await RunRulesetAsync(NftablesKillSwitchRenderer.RenderRemove(), cancellationToken)
            .ConfigureAwait(false);

        return removed.Succeeded
            ? KillSwitchApplyResult.Ok(removed.Combined)
            : KillSwitchApplyResult.Failed(RemoveFailed(removed.Combined), removed.Combined);
    }

    public async Task<KillSwitchState> InspectAsync(KillSwitchPlan? expected, CancellationToken cancellationToken)
    {
        if (!_runner.Exists("nft") || !_isElevated())
        {
            return new KillSwitchState
            {
                IsArmed = false,
                IsDrifted = false,
                MechanismName = MechanismName,
            };
        }

        var listed = await _runner
            .RunAsync("nft", new[] { "list", "table", "inet", NftablesKillSwitchRenderer.TableName },
                cancellationToken)
            .ConfigureAwait(false);

        if (!listed.Succeeded)
        {
            // A missing table is the normal "not armed" case; nft reports it on stderr.
            return new KillSwitchState
            {
                IsArmed = false,
                IsDrifted = false,
                MechanismName = MechanismName,
            };
        }

        var hasMarker = listed.StandardOutput.Contains(OwnershipMarker, StringComparison.Ordinal);

        // A same-named table without our marker means something else owns it, or a previous apply
        // was truncated. Both are drift, and both need to be surfaced rather than treated as armed.
        var orphans = hasMarker
            ? Array.Empty<string>()
            : new[] { $"inet {NftablesKillSwitchRenderer.TableName} exists but is not a complete MyVpn rule set" };

        return new KillSwitchState
        {
            IsArmed = hasMarker,
            IsDrifted = !hasMarker,
            OrphanedRules = orphans,
            MechanismName = MechanismName,
        };
    }

    // ------------------------------------------------------------------ internals

    /// <summary>
    /// Applies a rendered rule set from a private temporary file.
    /// </summary>
    /// <remarks>
    /// The file is created with owner-only permissions and removed in a <c>finally</c>. Writing it
    /// to disk rather than piping to stdin keeps the execution path a plain argv invocation with no
    /// shell, which is the same rule the rest of the platform layer follows.
    /// </remarks>
    private async Task<CommandResult> RunRulesetAsync(string ruleset, CancellationToken cancellationToken)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            $"myvpn-nft-{Guid.NewGuid():N}.nft");

        try
        {
            await File.WriteAllTextAsync(path, ruleset, cancellationToken).ConfigureAwait(false);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            return await _runner
                .RunAsync("nft", new[] { "--file", path }, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new CommandResult(-1, string.Empty, ex.Message);
        }
        finally
        {
            try
            {
                if (File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A leftover 0600 file in the temp directory is harmless.
            }
        }
    }

    private static MyVpnError ApplyFailed(string output) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.apply_failed",
            ErrorSeverity.Critical,
            $"nftables rejected the rule set: {Trim(output)}",
            "killswitch.reapply");

    private static MyVpnError RemoveFailed(string output) =>
        new MyVpnError(
            ErrorCodes.KillSwitchRemoveFailed,
            "error.killswitch.remove_failed",
            ErrorSeverity.Critical,
            $"nftables could not remove the rule set: {Trim(output)}",
            "network.restore");

    private static MyVpnError NotElevated() =>
        new MyVpnError(
            ErrorCodes.PrivilegeDenied,
            "error.killswitch.needs_privileges",
            ErrorSeverity.Error,
            "Applying firewall rules requires root. MyVpn needs its privileged helper installed; "
            + "the UI must never run as root itself.",
            "privilege.install_helper");

    private static string Trim(string value) =>
        value.Length <= 300 ? value : value[..300] + "…";

    private static bool DefaultElevationCheck()
    {
        if (OperatingSystem.IsWindows())
        {
            return false;
        }

        try
        {
            return GetEffectiveUserId() == 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
    }

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();
}
