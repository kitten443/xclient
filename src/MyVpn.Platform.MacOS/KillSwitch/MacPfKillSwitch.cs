using System.Globalization;
using System.Runtime.InteropServices;
using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Execution;
using MyVpn.Platform.Abstractions.KillSwitch;

namespace MyVpn.Platform.MacOS.KillSwitch;

/// <summary>
/// Every <c>pfctl</c> (and <c>ifconfig</c>) argv vector MyVpn can issue, as pure functions.
/// </summary>
/// <remarks>
/// <para>
/// Pulling the command lines out of the executor is not cosmetic. The two rules that matter most on
/// macOS are properties of the argv, not of the flow around it:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <c>pfctl -d</c> must never be issued. XNU's <c>DIOCSTOP</c> handler runs
/// <c>pf_stop(); pf_enabled_ref_count = 0; invalidate_all_tokens();</c> — it disables PF outright and
/// destroys every other enabler's token, including the Application Firewall's
/// (<c>com.apple/250.ApplicationFirewall</c>). Likewise <c>-e</c> is forbidden: it takes no token,
/// so the reference it creates can never be released selectively.
/// </description></item>
/// <item><description>
/// <c>-X</c> may only ever be issued with MyVpn's own captured, non-zero token. <c>-X 0</c> is not a
/// global shutdown (it merely returns <c>EINVAL</c>), but shipping it means the reference that was
/// taken is leaked and PF stays enabled for the rest of the boot.
/// </description></item>
/// </list>
/// <para>
/// The test suite asserts both properties over <see cref="AllShapes"/>, so a future command that
/// reintroduces <c>-d</c> or <c>-e</c> fails the build rather than the field.
/// </para>
/// </remarks>
public static class PfctlCommands
{
    /// <summary>The command-line tool that drives Packet Filter on macOS.</summary>
    public const string PfctlBinary = "pfctl";

    /// <summary>The interface-observation tool used for the tunnel pre-flight check.</summary>
    public const string IfconfigBinary = "ifconfig";

    /// <summary>Placeholder used by <see cref="AllShapes"/> in place of a temporary file path.</summary>
    public const string RulesetFilePlaceholder = "/tmp/myvpn-pf-ruleset.conf";

    /// <summary>Placeholder used by <see cref="AllShapes"/> in place of a real token.</summary>
    public const string TokenPlaceholder = "1234567890123";

    /// <summary>Longest accepted token, in digits. Tokens are 64-bit, so 20 digits cover them.</summary>
    public const int MaxTokenLength = 20;

    /// <summary>Enables PF and increments its reference count; the printed token is captured.</summary>
    public static IReadOnlyList<string> Enable() => new[] { "-E" };

    /// <summary>Releases the reference represented by <paramref name="token"/> (never <c>-d</c>).</summary>
    public static IReadOnlyList<string> Release(string token)
    {
        if (!IsValidToken(token))
        {
            // A malformed token is a programming error: the only correct values come from
            // pfctl's own output. Refusing here is what keeps '-X 0' out of the shipped binary.
            throw new ArgumentException(
                $"'{token}' is not a PF enable token: expected 1 to {MaxTokenLength} decimal digits "
                + "that are not all zero.",
                nameof(token));
        }

        return new[] { "-X", token };
    }

    /// <summary>Parse-checks a ruleset file without loading it (<c>-n</c>).</summary>
    public static IReadOnlyList<string> ParseCheck(string rulesetPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rulesetPath);
        return new[] { "-n", "-f", rulesetPath };
    }

    /// <summary>Loads a ruleset file. This replaces the main ruleset, Apple's anchors included.</summary>
    public static IReadOnlyList<string> Load(string rulesetPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rulesetPath);
        return new[] { "-f", rulesetPath };
    }

    /// <summary>
    /// Restores Apple's startup ruleset, the documented way back out of a main-ruleset replacement.
    /// </summary>
    public static IReadOnlyList<string> LoadStartupRuleset() =>
        new[] { "-f", PfAnchorRenderer.StartupRulesetPath };

    /// <summary>Flushes the state table, so flows that matched the previous ruleset stop passing.</summary>
    public static IReadOnlyList<string> FlushStates() => new[] { "-F", "states" };

    /// <summary>Shows the loaded filter rules; MyVpn's ownership marker appears in this output.</summary>
    public static IReadOnlyList<string> ShowRules() => new[] { "-s", "rules" };

    /// <summary>Shows the loaded tables.</summary>
    public static IReadOnlyList<string> ShowTables() => new[] { "-s", "Tables" };

    /// <summary>Shows the pf-enable references (pid/name/token), for verifying our own reference.</summary>
    public static IReadOnlyList<string> ShowReferences() => new[] { "-s", "References" };

    /// <summary>
    /// Replaces the server table's contents without a ruleset reload, so a re-resolved server
    /// address does not flush the state table.
    /// </summary>
    /// <remarks>
    /// An empty replacement is refused: <c>-T replace</c> with no addresses would empty the table,
    /// and a rule that passes traffic to an empty table matches nothing, which black-holes the
    /// tunnel while the terminal block keeps everything else closed.
    /// </remarks>
    public static IReadOnlyList<string> ReplaceServerTable(IReadOnlyCollection<string> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);

        if (addresses.Count == 0)
        {
            throw new ArgumentException(
                "Refusing to replace the PF server table with an empty list: it would black-hole "
                + "the tunnel's own transport.",
                nameof(addresses));
        }

        var arguments = new List<string>(4 + addresses.Count)
        {
            "-t", PfAnchorRenderer.ServerTableName, "-T", "replace",
        };

        arguments.AddRange(addresses);
        return arguments;
    }

    /// <summary>Probes an interface, used to prove the tunnel name is real before arming a block.</summary>
    public static IReadOnlyList<string> ProbeInterface(string interfaceName)
    {
        if (!PfAnchorRenderer.IsSafeInterfaceName(interfaceName))
        {
            throw new ArgumentException(
                $"'{interfaceName}' is not a usable interface name to hand to ifconfig.",
                nameof(interfaceName));
        }

        return new[] { interfaceName };
    }

    /// <summary>
    /// Every argv shape this class can produce, including the ones the executor issues on paths a
    /// unit test cannot reach on a non-macOS host.
    /// </summary>
    /// <remarks>
    /// Exists so the safety properties can be asserted exhaustively: the tests walk this list and
    /// fail if <c>-d</c> or <c>-e</c> appears anywhere, or if <c>-X</c> is ever paired with anything
    /// but a token.
    /// </remarks>
    public static IReadOnlyList<IReadOnlyList<string>> AllShapes() => new[]
    {
        Enable(),
        ParseCheck(RulesetFilePlaceholder),
        Load(RulesetFilePlaceholder),
        LoadStartupRuleset(),
        FlushStates(),
        Release(TokenPlaceholder),
        ShowRules(),
        ShowTables(),
        ShowReferences(),
        ReplaceServerTable(new[] { "203.0.113.5" }),
        ProbeInterface("utun0"),
    };

    /// <summary>True when <paramref name="token"/> is a plausible PF enable token.</summary>
    public static bool IsValidToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length > MaxTokenLength)
        {
            return false;
        }

        var nonZeroSeen = false;

        foreach (var c in token)
        {
            if (!char.IsAsciiDigit(c))
            {
                return false;
            }

            nonZeroSeen |= c != '0';
        }

        return nonZeroSeen;
    }
}

/// <summary>
/// Pure parsers and renderers for the text <c>pfctl</c> produces and consumes.
/// </summary>
/// <remarks>
/// Kept separate from the executor so the parsing — the part that decides whether the kill switch is
/// really armed, and which token may be released — is unit-tested on any host. <c>pfctl</c> output
/// is explicitly unstable across releases, so every parse is strict: an unrecognised shape is
/// reported as a failure with the raw output attached, never guessed at.
/// </remarks>
public static class PfctlOutput
{
    /// <summary>Marker line written above the token in the on-disk reference file.</summary>
    public const string TokenFileHeader =
        "# MyVpn PF enable reference. Release it with: pfctl -X <token>";

    /// <summary>
    /// Extracts the token from <c>pfctl -E</c> output, whose documented shape is
    /// <c>pf enabled\nToken : 1234567890</c>.
    /// </summary>
    /// <remarks>
    /// The search is for a line containing the word "token" followed by a decimal number. A
    /// format the parser does not recognise returns <c>false</c> so the caller can report that PF
    /// was enabled with a reference it cannot release — a loud, actionable failure, and far better
    /// than releasing a guessed value.
    /// </remarks>
    public static bool TryParseEnableToken(string? output, out string token)
    {
        token = string.Empty;

        if (string.IsNullOrEmpty(output))
        {
            return false;
        }

        foreach (var rawLine in output.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || !line.Contains("token", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var digits = LastDigitRun(line);
            if (digits.Length > 0 && PfctlCommands.IsValidToken(digits))
            {
                token = digits;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// True when <paramref name="token"/> appears in <c>pfctl -s References</c> output.
    /// </summary>
    /// <remarks>
    /// A digit-delimited substring search rather than a column parse, because the reference listing's
    /// layout is not documented and has changed between releases. It cannot produce a false
    /// positive for a different token: the surrounding characters must not be digits.
    /// </remarks>
    public static bool ContainsToken(string? output, string token)
    {
        if (string.IsNullOrEmpty(output) || !PfctlCommands.IsValidToken(token))
        {
            return false;
        }

        var index = 0;
        while (true)
        {
            index = output.IndexOf(token, index, StringComparison.Ordinal);
            if (index < 0)
            {
                return false;
            }

            var beforeOk = index == 0 || !char.IsAsciiDigit(output[index - 1]);
            var afterIndex = index + token.Length;
            var afterOk = afterIndex >= output.Length || !char.IsAsciiDigit(output[afterIndex]);

            if (beforeOk && afterOk)
            {
                return true;
            }

            index++;
        }
    }

    /// <summary>Renders the on-disk reference file for a captured token.</summary>
    public static string RenderStoredToken(string token)
    {
        if (!PfctlCommands.IsValidToken(token))
        {
            throw new ArgumentException($"'{token}' is not a PF enable token.", nameof(token));
        }

        return TokenFileHeader + "\n" + token + "\n";
    }

    /// <summary>
    /// Reads the token back from the reference file, ignoring comments and blank lines.
    /// </summary>
    public static bool TryParseStoredToken(string? contents, out string token)
    {
        token = string.Empty;

        if (string.IsNullOrEmpty(contents))
        {
            return false;
        }

        foreach (var rawLine in contents.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            if (!PfctlCommands.IsValidToken(line))
            {
                return false;
            }

            token = line;
            return true;
        }

        return false;
    }

    /// <summary>Returns the last run of decimal digits in a line, or an empty string.</summary>
    private static string LastDigitRun(string line)
    {
        var end = -1;

        for (var i = line.Length - 1; i >= 0; i--)
        {
            if (!char.IsAsciiDigit(line[i]))
            {
                continue;
            }

            end = i;
            break;
        }

        if (end < 0)
        {
            return string.Empty;
        }

        var start = end;
        while (start > 0 && char.IsAsciiDigit(line[start - 1]))
        {
            start--;
        }

        return line[start..(end + 1)];
    }
}

/// <summary>
/// Applies the Kill Switch through macOS Packet Filter.
/// </summary>
/// <remarks>
/// <para>
/// <b>Best effort, not API — and that caveat is part of the design, not a disclaimer.</b> Apple
/// Technote TN3165, "Packet Filter is not API", states verbatim that PF <i>"is not considered API.
/// Do not use Packet Filter in a software product that you distribute to a wide audience"</i> and
/// tells developers to migrate to Network Extension. PF stays because it is the only fail-closed
/// mechanism available without the Network Extension entitlement, so:
/// <c>PlatformCapabilities.KillSwitchIsBestEffort</c> is set for macOS, the generated ruleset carries
/// the same warning in its header, and TN3165's own test list (Internet Sharing, AirDrop, Continuity,
/// Xcode device debugging, Mac Virtual Display) is the acceptance checklist. The mechanism is
/// isolated behind <see cref="IKillSwitch"/> so it can be replaced by an
/// <c>NEPacketTunnelProvider</c>-based one if the entitlement is ever obtained.
/// </para>
/// <para>
/// <b>Reference discipline.</b> PF is enabled with <c>pfctl -E</c> and the token it prints is
/// captured and persisted (see the token file below). Shutdown releases <i>that</i> token with
/// <c>pfctl -X</c>. <c>pfctl -d</c> is never issued: XNU's <c>DIOCSTOP</c> zeroes the enable
/// reference count and invalidates every token, which would take the Application Firewall's own
/// <c>com.apple/250.ApplicationFirewall</c> rules down with it. <c>pfctl -e</c> is never issued
/// either, because a reference taken without a token can never be released selectively. The token
/// file lives under <c>/var/run</c>, which the OS clears at boot — the same lifetime PF's enable
/// state has, so a token never outlives the state it refers to.
/// </para>
/// <para>
/// <b>Sequence.</b> The interface is probed first, then the ruleset is parse-checked
/// (<c>pfctl -n -f</c>), then PF is enabled (<c>pfctl -E</c>, token captured), then the ruleset is
/// loaded (<c>pfctl -f</c>), then the state table is flushed (<c>pfctl -F states</c>). The order is
/// the researched one and each step has a reason: the parse check costs nothing and catches a
/// ruleset mistake before PF is touched; states outlive rules, so a stricter ruleset does not stop
/// flows that already have state — hence the flush, which is what makes the switch take effect
/// rather than merely exist.
/// </para>
/// <para>
/// <b>Deviation from the brief, stated plainly: <c>-f -</c> is written as a temporary file.</b>
/// The researched commands are <c>pfctl -n -f -</c> and <c>pfctl -f -</c>, reading the ruleset from
/// stdin. <see cref="ICommandRunner"/> has no stdin parameter and cannot be given one from this
/// assembly, so the ruleset is written to a private file created with owner-only permissions and
/// deleted in a <c>finally</c> block, and the same <c>-f &lt;path&gt;</c> verb is used. This is an
/// interface gap worth closing (an <c>ICommandRunner</c> overload taking stdin), not a shortcut:
/// nothing about the argv-only rule is relaxed, and no shell is involved anywhere in this class.
/// </para>
/// <para>
/// <b>The utun name is the sharp edge.</b> macOS assigns <c>utunN</c> dynamically, and PF accepts a
/// rule naming an interface that does not exist yet (XNU creates the <c>pfi_kif</c> entry at load
/// time and binds it when the interface attaches). So a wrong name produces no error at all: the
/// tunnel pass matches nothing, the terminal block catches everything, and the user has a
/// fail-closed but broken VPN with a clean exit code. Two defences are therefore in place:
/// <see cref="ApplyAsync"/> refuses to arm when the interface does not exist, and
/// <see cref="InspectAsync"/> reports drift when the loaded rules do not mention the expected
/// interface.
/// </para>
/// <para>
/// <b>Server address churn.</b> The endpoints live in a <c>persist</c> PF table, and
/// <see cref="UpdateServerTableAsync"/> replaces its contents with <c>-T replace</c> — which does
/// not flush states and does not reload the ruleset. The table is never initialised with an empty
/// list: <c>pf.conf(5)</c> says a table "initialized with the empty list, <c>{ }</c>, will be
/// cleared on load", and an empty server table means the tunnel's own transport is blocked.
/// </para>
/// <para>
/// <b>Per-process routing is not implemented, by design.</b> PF's <c>user</c>/<c>group</c> are match
/// criteria only — they cannot appear on <c>nat</c>/<c>rdr</c>, they cover TCP and UDP only, and the
/// credentials are frozen when the socket is created, which also means DNS (attributed to
/// <c>_mdnsresponder</c>) cannot be classified per application. A <c>user</c>-scoped <c>route-to</c>
/// is syntactically possible but is directional only, does not rewrite source addresses, needs a
/// valid next hop for a point-to-point utun, and is unproven; <c>rtable</c> is inbound-only;
/// <c>ipfw</c> is gone from current XNU; <c>NEAppRule</c> is read-only to the provider and installed
/// by a managed profile; <c>NEFilterDataProvider</c> cannot relay. The achievable approximations are
/// destination-based split tunnelling, UID-based <i>block</i>-lists and app-level proxy settings.
/// Nobody should "add" per-app tunnelling here without reading
/// <c>docs/research/08-macos-networking.md</c> §1.4.7 first.
/// </para>
/// </remarks>
public sealed class MacPfKillSwitch : IKillSwitch
{
    /// <summary>
    /// Where MyVpn's PF enable token is persisted between processes.
    /// </summary>
    /// <remarks>
    /// <c>/var/run</c> is writable by root, is not preserved across a reboot, and is exactly the
    /// lifetime the token has: PF's enable state does not survive a reboot either.
    /// </remarks>
    public const string DefaultTokenPath = "/var/run/myvpn.pf.token";

    private readonly ICommandRunner _runner;
    private readonly Func<bool> _isElevated;
    private readonly string _tokenPath;

    public MacPfKillSwitch(
        ICommandRunner? runner = null,
        Func<bool>? isElevated = null,
        string? tokenPath = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tokenPath ?? DefaultTokenPath);

        _runner = runner ?? new ProcessCommandRunner();
        _isElevated = isElevated ?? DefaultElevationCheck;
        _tokenPath = tokenPath ?? DefaultTokenPath;
    }

    /// <summary>Human-readable mechanism name; matches <c>KillSwitchMechanism.PfAnchors</c>.</summary>
    public string MechanismName => "pf";

    /// <summary>
    /// True when this is macOS, <c>pfctl</c> is present, and this process may drive it.
    /// </summary>
    /// <remarks>
    /// The operating-system check comes first and is not negotiable: every other member of this class
    /// touches <c>pfctl</c>, <c>ifconfig</c> and <c>/var/run</c>, none of which exist on the hosts
    /// where the test suite runs. <c>IsSupported</c> is also deliberately cheap — no process is
    /// spawned — because it is read by capability reporting in the UI.
    /// </remarks>
    public bool IsSupported =>
        OperatingSystem.IsMacOS() && _runner.Exists(PfctlCommands.PfctlBinary) && _isElevated();

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

        var guard = Guard();
        if (guard is not null)
        {
            return guard;
        }

        var rendered = PfAnchorRenderer.RenderInstall(plan);
        if (rendered.IsFailure)
        {
            return KillSwitchApplyResult.Failed(rendered.Error!);
        }

        // Prove the tunnel interface exists before replacing a ruleset whose terminal rule drops
        // everything. PF would accept the name silently, so this check is the only thing standing
        // between a typo and a fail-closed-but-broken tunnel.
        var probe = await ProbeTunnelInterfaceAsync(plan.TunnelInterface, cancellationToken)
            .ConfigureAwait(false);

        if (probe.IsFailure)
        {
            return KillSwitchApplyResult.Failed(probe.Error!);
        }

        var file = await WriteRulesetFileAsync(rendered.Value, cancellationToken).ConfigureAwait(false);
        if (file.IsFailure)
        {
            return KillSwitchApplyResult.Failed(file.Error!);
        }

        var path = file.Value;

        try
        {
            // (1) Parse-check first: it costs one process and catches a ruleset mistake before PF is
            //     touched at all, so a bad plan never leaves a half-armed machine.
            var checkedRules = await RunAsync(PfctlCommands.ParseCheck(path), cancellationToken)
                .ConfigureAwait(false);

            if (!checkedRules.Succeeded)
            {
                return KillSwitchApplyResult.Failed(
                    ParseCheckFailed(checkedRules), checkedRules.Combined);
            }

            // (2) Take (or reuse) the enable reference *after* the ruleset is known to parse.
            var reference = await EnsureReferenceAsync(cancellationToken).ConfigureAwait(false);
            if (reference.IsFailure)
            {
                return KillSwitchApplyResult.Failed(reference.Error!);
            }

            var token = reference.Value;

            // (3) Load. -f replaces the main ruleset, which is why the rendered file re-declares
            //     Apple's anchors.
            var loaded = await RunAsync(PfctlCommands.Load(path), cancellationToken).ConfigureAwait(false);
            if (!loaded.Succeeded)
            {
                // Roll back the reference we just took: nothing of ours is armed, so holding it
                // would only keep PF enabled for the rest of the boot.
                await ReleaseReferenceAsync(token, cancellationToken).ConfigureAwait(false);
                return KillSwitchApplyResult.Failed(ApplyFailed(loaded), loaded.Combined);
            }

            // (4) States outlive rules. Without this flush, flows that matched the previous ruleset
            //     keep passing and the switch only appears to be in force.
            var flushed = await RunAsync(PfctlCommands.FlushStates(), cancellationToken)
                .ConfigureAwait(false);

            if (!flushed.Succeeded)
            {
                // The rules are loaded and PF is enabled, so the reference is deliberately *not*
                // released: releasing it would disable the block and fail open. The caller is told
                // the truth — armed, but existing flows were not invalidated.
                return KillSwitchApplyResult.Failed(StateFlushFailed(flushed), flushed.Combined);
            }

            return KillSwitchApplyResult.Ok(
                $"PF armed: {checkedRules.Combined} {loaded.Combined} {flushed.Combined}".Trim());
        }
        finally
        {
            DeleteFile(path);
        }
    }

    /// <summary>
    /// Replaces the contents of the server table without reloading the ruleset.
    /// </summary>
    /// <remarks>
    /// This is the server-address-churn path: when the profile's hostname re-resolves, the new
    /// addresses go into the table with <c>-T replace</c>, which — unlike a ruleset reload — does not
    /// flush the state table and does not disturb Apple's anchors. The table is never replaced with an
    /// empty list; see <see cref="PfctlCommands.ReplaceServerTable"/>.
    /// </remarks>
    public async Task<KillSwitchApplyResult> UpdateServerTableAsync(
        KillSwitchPlan plan,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var guard = Guard();
        if (guard is not null)
        {
            return guard;
        }

        if (plan.AllowedEndpoints.Count == 0)
        {
            return KillSwitchApplyResult.Failed(new MyVpnError(
                ErrorCodes.KillSwitchApplyFailed,
                "error.killswitch.no_server_endpoint",
                ErrorSeverity.Critical,
                "Refusing to empty the PF server table: the pass rules would match nothing and the "
                + "tunnel's own transport would be blocked.",
                "killswitch.reapply"));
        }

        var addresses = plan.AllowedEndpoints
            .Select(e => e.Destination)
            .Distinct()
            .OrderBy(b => b.IsIPv4 ? 0 : 1)
            .ThenBy(b => b.PrefixLength)
            .ThenBy(b => b.Network.ToString(), StringComparer.Ordinal)
            .Select(b => b.PrefixLength == (b.IsIPv4 ? 32 : 128) ? b.Network.ToString() : b.ToString())
            .ToArray();

        var updated = await RunAsync(PfctlCommands.ReplaceServerTable(addresses), cancellationToken)
            .ConfigureAwait(false);

        return updated.Succeeded
            ? KillSwitchApplyResult.Ok(updated.Combined)
            : KillSwitchApplyResult.Failed(TableUpdateFailed(updated), updated.Combined);
    }

    public async Task<KillSwitchApplyResult> RemoveAsync(string identifier, CancellationToken cancellationToken)
    {
        var guard = Guard(allowMissingTool: true);
        if (guard is not null)
        {
            return guard;
        }

        if (!_runner.Exists(PfctlCommands.PfctlBinary))
        {
            // Apply refuses to run without the tool, so nothing can have been installed by us.
            return KillSwitchApplyResult.Ok("pfctl is not installed; nothing to remove.");
        }

        var rules = await RunAsync(PfctlCommands.ShowRules(), cancellationToken).ConfigureAwait(false);

        if (!rules.Succeeded)
        {
            // Without being able to read the loaded rules there is no way to tell whether MyVpn owns
            // the current ruleset, and replacing another product's ruleset is worse than reporting
            // that the state could not be established.
            return KillSwitchApplyResult.Failed(ProbeFailed(rules), rules.Combined);
        }

        var token = ReadStoredToken();
        var ownsRules = rules.StandardOutput.Contains(
            PfAnchorRenderer.OwnershipMarker, StringComparison.Ordinal);

        if (token is null && !ownsRules)
        {
            // Idempotent no-op. Note what is deliberately *not* done here: /etc/pf.conf is not
            // reloaded, because flushing a main ruleset MyVpn never installed would break whatever
            // did install it.
            return KillSwitchApplyResult.Ok("No MyVpn PF ruleset is loaded and no enable reference is held.");
        }

        var failures = new List<string>();

        // (1) Restore Apple's startup ruleset — the documented way back out of a main-ruleset
        //     replacement. If that fails, load the permissive ruleset instead: the machine must not
        //     be left blocked by rules whose owner is going away.
        var restored = await RunAsync(PfctlCommands.LoadStartupRuleset(), cancellationToken)
            .ConfigureAwait(false);

        if (!restored.Succeeded)
        {
            failures.Add($"loading {PfAnchorRenderer.StartupRulesetPath} failed: {Trim(restored.Combined)}");

            var disarm = PfAnchorRenderer.RenderDisarm();
            if (disarm.IsSuccess)
            {
                var file = await WriteRulesetFileAsync(disarm.Value, cancellationToken).ConfigureAwait(false);
                if (file.IsFailure)
                {
                    failures.Add(Describe(file.Error!));
                }
                else
                {
                    try
                    {
                        var fallback = await RunAsync(PfctlCommands.Load(file.Value), cancellationToken)
                            .ConfigureAwait(false);

                        if (!fallback.Succeeded)
                        {
                            failures.Add($"loading the teardown ruleset failed: {Trim(fallback.Combined)}");
                        }
                    }
                    finally
                    {
                        DeleteFile(file.Value);
                    }
                }
            }
        }

        // (2) Release only our own reference, and only after the ruleset is gone: releasing first
        //     would disable PF while MyVpn's block was still loaded, which is a fail-open window.
        if (token is not null)
        {
            var released = await RunAsync(PfctlCommands.Release(token), cancellationToken)
                .ConfigureAwait(false);

            if (released.Succeeded)
            {
                DeleteFile(_tokenPath);
            }
            else if (!failures.Any(f => f.Contains("enable reference", StringComparison.Ordinal)))
            {
                // The token is kept on disk so a later attempt can still release it.
                failures.Add(
                    $"releasing the PF enable reference (token {token}) failed: {Trim(released.Combined)}");
            }
        }

        return failures.Count == 0
            ? KillSwitchApplyResult.Ok("PF Kill Switch removed; Apple's startup ruleset restored.")
            : KillSwitchApplyResult.Failed(RemoveFailed(string.Join("; ", failures)));
    }

    /// <summary>
    /// Reads the live ruleset back and compares it with what MyVpn believes it installed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three independent things are checked, because each has failed in the field for someone:
    /// </para>
    /// <list type="number">
    /// <item><description>the ownership marker is present, so the loaded rules are ours at all;</description></item>
    /// <item><description>
    /// the expected tunnel interface is referenced, which is the only way to catch the silent
    /// wrong-utun-name failure — <c>pfctl -n</c> accepts a name that does not exist;
    /// </description></item>
    /// <item><description>
    /// our enable reference is still held. Rules stay loaded while PF is disabled, so finding our
    /// rules is not the same as being protected: if the token is gone from
    /// <c>pfctl -s References</c>, the filter is not running and reporting "armed" would be a lie.
    /// A reference listing in an unrecognised format can produce a false "not armed" — the safe
    /// direction, and it is reported rather than hidden.
    /// </description></item>
    /// </list>
    /// </remarks>
    public async Task<KillSwitchState> InspectAsync(
        KillSwitchPlan? expected,
        CancellationToken cancellationToken)
    {
        if (!IsSupported)
        {
            return new KillSwitchState
            {
                IsArmed = false,
                IsDrifted = false,
                MechanismName = MechanismName,
            };
        }

        var rules = await RunAsync(PfctlCommands.ShowRules(), cancellationToken).ConfigureAwait(false);

        if (!rules.Succeeded)
        {
            return new KillSwitchState
            {
                IsArmed = false,
                IsDrifted = false,
                MechanismName = MechanismName,
            };
        }

        var hasMarker = rules.StandardOutput.Contains(
            PfAnchorRenderer.OwnershipMarker, StringComparison.Ordinal);

        var details = new List<string>();
        var armed = hasMarker;
        var drifted = false;

        if (hasMarker && expected is not null)
        {
            if (expected.Mode == KillSwitchMode.Disabled)
            {
                drifted = true;
                details.Add("MyVpn's rules are loaded but the expected plan is Disabled.");
            }
            else if (PfAnchorRenderer.TryGetSafeInterfaceName(
                         expected.TunnelInterface, out var tunnelInterface)
                     && !rules.StandardOutput.Contains($"on {tunnelInterface}", StringComparison.Ordinal))
            {
                drifted = true;
                details.Add(
                    $"the loaded ruleset does not reference the expected tunnel interface "
                    + $"'{tunnelInterface}' — PF accepts a name for an interface that does not exist, "
                    + "so this is the silent fail-closed-but-broken case.");
            }
        }

        var token = ReadStoredToken();
        if (token is not null)
        {
            var references = await RunAsync(PfctlCommands.ShowReferences(), cancellationToken)
                .ConfigureAwait(false);

            if (references.Succeeded && !PfctlOutput.ContainsToken(references.StandardOutput, token))
            {
                armed = false;
                drifted = true;
                details.Add(
                    $"PF no longer holds MyVpn's enable reference (token {token}); the rules may be "
                    + "loaded but the filter is not running.");
            }
        }

        return new KillSwitchState
        {
            IsArmed = armed,
            IsDrifted = drifted,
            OrphanedRules = details,
            MechanismName = MechanismName,
        };
    }

    // ------------------------------------------------------------------ error mapping (pure)

    /// <summary>Error for a call made on a host that is not macOS.</summary>
    public static MyVpnError UnsupportedOnThisHost() =>
        new MyVpnError(
            ErrorCodes.PlatformUnsupported,
            "error.platform.macos_only",
            ErrorSeverity.Error,
            "The PF Kill Switch drives 'pfctl', which only exists on macOS. This call is refused "
            + "before any process is started.",
            "diagnostics.run");

    /// <summary>Error for a missing <c>pfctl</c>.</summary>
    public static MyVpnError ToolMissing() =>
        new MyVpnError(
            ErrorCodes.PlatformToolMissing,
            "error.platform.tool_missing",
            ErrorSeverity.Error,
            "The 'pfctl' tool was not found, so the Kill Switch cannot be applied.",
            "diagnostics.run")
            .WithArg("tool", PfctlCommands.PfctlBinary);

    /// <summary>Error for an unprivileged process.</summary>
    public static MyVpnError NotElevated() =>
        new MyVpnError(
            ErrorCodes.PrivilegeDenied,
            "error.killswitch.needs_privileges",
            ErrorSeverity.Error,
            "Driving pfctl requires root. MyVpn needs its privileged helper installed; the UI must "
            + "never run as root itself.",
            "privilege.install_helper");

    /// <summary>Error for an interface name that is not a plain interface identifier.</summary>
    public static MyVpnError TunnelInterfaceInvalid(string? interfaceName) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.tunnel_interface_invalid",
            ErrorSeverity.Error,
            $"'{interfaceName}' cannot be used as a PF interface name; PF will accept a name for an "
            + "interface that does not exist, so a bad name would fail closed and silent.",
            "diagnostics.run");

    /// <summary>Error for a tunnel interface that does not exist (yet).</summary>
    public static MyVpnError TunnelInterfaceMissing(string interfaceName, string? output) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.tunnel_interface_missing",
            ErrorSeverity.Critical,
            $"The tunnel interface '{interfaceName}' does not exist, so arming a ruleset whose "
            + "terminal rule drops everything would black-hole the tunnel. macOS assigns utunN "
            + "dynamically: resolve the name the core actually created and try again. "
            + $"ifconfig said: {Trim(output)}",
            "killswitch.reapply");

    /// <summary>Error for a ruleset the parser rejected.</summary>
    public static MyVpnError ParseCheckFailed(CommandResult result) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.pf_parse_failed",
            ErrorSeverity.Error,
            $"pfctl rejected the generated ruleset during the parse-only check, so nothing was "
            + $"armed: {Trim(result.Combined)}",
            "killswitch.reapply");

    /// <summary>Error for a ruleset PF refused to load.</summary>
    public static MyVpnError ApplyFailed(CommandResult result) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.apply_failed",
            ErrorSeverity.Critical,
            $"pfctl could not load the ruleset: {Trim(result.Combined)}",
            "killswitch.reapply");

    /// <summary>Error for a failed state flush; the rules are loaded but old flows may survive.</summary>
    public static MyVpnError StateFlushFailed(CommandResult result) =>
        new MyVpnError(
            ErrorCodes.KillSwitchVerificationFailed,
            "error.killswitch.pf_state_flush_failed",
            ErrorSeverity.Critical,
            "The ruleset is loaded and PF is enabled, but 'pfctl -F states' failed, so flows that "
            + "already had state may keep passing until they expire. The enable reference is "
            + $"deliberately kept: releasing it would fail open. pfctl said: {Trim(result.Combined)}",
            "killswitch.reapply");

    /// <summary>Error for a failed server-table update.</summary>
    public static MyVpnError TableUpdateFailed(CommandResult result) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.pf_table_update_failed",
            ErrorSeverity.Error,
            $"The PF server table could not be replaced: {Trim(result.Combined)}",
            "killswitch.reapply");

    /// <summary>Error for a failed read of the pf-enable reference list.</summary>
    public static MyVpnError ReferenceProbeFailed(CommandResult result) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.pf_reference_probe_failed",
            ErrorSeverity.Error,
            "MyVpn already holds a PF enable reference but could not read 'pfctl -s References' to "
            + "confirm it is still valid. Taking a second reference would leak one for the rest of "
            + $"the boot, so the apply was refused. pfctl said: {Trim(result.Combined)}",
            "killswitch.reapply");

    /// <summary>Error for a failed <c>pfctl -E</c>.</summary>
    public static MyVpnError EnableFailed(CommandResult result) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.pf_enable_failed",
            ErrorSeverity.Critical,
            $"PF could not be enabled with a reference: {Trim(result.Combined)}",
            "killswitch.reapply");

    /// <summary>
    /// Error for <c>pfctl -E</c> output whose token could not be parsed.
    /// </summary>
    /// <remarks>
    /// The honest and unpleasant case: PF has been enabled with a reference MyVpn cannot release.
    /// Reporting it with the raw output is the only useful action, because the operator can release
    /// it by hand from <c>pfctl -s References</c>.
    /// </remarks>
    public static MyVpnError TokenUnparsed(CommandResult result) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.pf_token_unparsed",
            ErrorSeverity.Critical,
            "PF was enabled but the token printed by 'pfctl -E' could not be parsed, so MyVpn cannot "
            + "release its own reference. Run 'pfctl -s References' and release the matching token "
            + $"with 'pfctl -X <token>'. Raw output: {Trim(result.Combined)}",
            "diagnostics.run");

    /// <summary>Error for a ruleset file that could not be written.</summary>
    public static MyVpnError RulesetFileFailed(string detail) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.pf_ruleset_file_failed",
            ErrorSeverity.Error,
            $"The generated ruleset could not be staged for pfctl: {detail}",
            "diagnostics.run");

    /// <summary>Error for a failed teardown.</summary>
    public static MyVpnError RemoveFailed(string detail) =>
        new MyVpnError(
            ErrorCodes.KillSwitchRemoveFailed,
            "error.killswitch.remove_failed",
            ErrorSeverity.Critical,
            $"The PF Kill Switch could not be fully removed: {detail}",
            "network.restore");

    /// <summary>Error for a failed read of the loaded rules.</summary>
    public static MyVpnError ProbeFailed(CommandResult result) =>
        new MyVpnError(
            ErrorCodes.KillSwitchRemoveFailed,
            "error.killswitch.pf_probe_failed",
            ErrorSeverity.Error,
            "The loaded PF ruleset could not be read, so MyVpn cannot tell whether it owns it. "
            + $"Replacing a ruleset that may belong to another product is worse than stopping. "
            + $"pfctl said: {Trim(result.Combined)}",
            "network.restore");

    // ------------------------------------------------------------------ internals

    /// <summary>
    /// Shared pre-flight. Returns <c>null</c> when the call may proceed, or the failure to return.
    /// </summary>
    private KillSwitchApplyResult? Guard(bool allowMissingTool = false)
    {
        // The operating-system check is first and unconditional: everything below it starts a
        // macOS-only process or touches a macOS-only path.
        if (!OperatingSystem.IsMacOS())
        {
            return KillSwitchApplyResult.Failed(UnsupportedOnThisHost());
        }

        if (!allowMissingTool && !_runner.Exists(PfctlCommands.PfctlBinary))
        {
            return KillSwitchApplyResult.Failed(ToolMissing());
        }

        if (!_isElevated())
        {
            return KillSwitchApplyResult.Failed(NotElevated());
        }

        return null;
    }

    private async Task<Result> ProbeTunnelInterfaceAsync(string interfaceName, CancellationToken cancellationToken)
    {
        if (!PfAnchorRenderer.TryGetSafeInterfaceName(interfaceName, out var safeName))
        {
            return Result.Fail(TunnelInterfaceInvalid(interfaceName));
        }

        if (!_runner.Exists(PfctlCommands.IfconfigBinary))
        {
            // Without ifconfig the only source of truth is gone. PF accepts names for interfaces
            // that do not exist, so refusing is the fail-closed choice.
            return Result.Fail(TunnelInterfaceMissing(safeName, "ifconfig is not available"));
        }

        var probe = await RunAsync(PfctlCommands.ProbeInterface(safeName), cancellationToken)
            .ConfigureAwait(false);

        return probe.Succeeded
            ? Result.Ok()
            : Result.Fail(TunnelInterfaceMissing(safeName, probe.Combined));
    }

    /// <summary>
    /// Returns the enable token MyVpn already holds, taking a new reference only when it does not.
    /// </summary>
    /// <remarks>
    /// Applying a plan twice must not take two references: each one would have to be released
    /// separately, and a leaked reference keeps PF enabled for the rest of the boot. A stored token
    /// that no longer appears in <c>pfctl -s References</c> is stale (the machine rebooted, or another
    /// tool disabled PF) and is replaced.
    /// </remarks>
    private async Task<Result<string>> EnsureReferenceAsync(CancellationToken cancellationToken)
    {
        var stored = ReadStoredToken();

        if (stored is not null)
        {
            var references = await RunAsync(PfctlCommands.ShowReferences(), cancellationToken)
                .ConfigureAwait(false);

            if (!references.Succeeded)
            {
                return Result<string>.Fail(ReferenceProbeFailed(references));
            }

            if (PfctlOutput.ContainsToken(references.StandardOutput, stored))
            {
                return Result<string>.Ok(stored);
            }

            DeleteFile(_tokenPath);
        }

        var enabled = await RunAsync(PfctlCommands.Enable(), cancellationToken).ConfigureAwait(false);

        if (!enabled.Succeeded)
        {
            return Result<string>.Fail(EnableFailed(enabled));
        }

        if (!PfctlOutput.TryParseEnableToken(enabled.Combined, out var token))
        {
            return Result<string>.Fail(TokenUnparsed(enabled));
        }

        var written = WriteTokenFile(token);
        if (written.IsFailure)
        {
            // The reference exists but cannot be remembered. Releasing it immediately is the only
            // way to leave the machine as it was found.
            await RunAsync(PfctlCommands.Release(token), cancellationToken).ConfigureAwait(false);
            return Result<string>.Fail(written.Error!);
        }

        return Result<string>.Ok(token);
    }

    /// <summary>Releases a reference MyVpn took moments ago, during a failed apply.</summary>
    private async Task ReleaseReferenceAsync(string token, CancellationToken cancellationToken)
    {
        var released = await RunAsync(PfctlCommands.Release(token), cancellationToken).ConfigureAwait(false);

        if (released.Succeeded)
        {
            DeleteFile(_tokenPath);
        }
    }

    /// <summary>
    /// Writes the ruleset to a private file for <c>pfctl -f</c>.
    /// </summary>
    /// <remarks>
    /// The researched form is <c>-f -</c> on stdin, which <see cref="ICommandRunner"/> cannot
    /// express; see the class remarks. The file is created with owner-only permissions and removed by
    /// the caller in a <c>finally</c>. It is not written to a fixed path, so two applies cannot race.
    /// </remarks>
    private async Task<Result<string>> WriteRulesetFileAsync(string ruleset, CancellationToken cancellationToken)
    {
        var path = Path.Combine(
            Path.GetTempPath(),
            string.Create(CultureInfo.InvariantCulture, $"myvpn-pf-{Guid.NewGuid():N}.conf"));

        try
        {
            await File.WriteAllTextAsync(path, ruleset, cancellationToken).ConfigureAwait(false);

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            return Result<string>.Ok(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result<string>.Fail(RulesetFileFailed($"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    private Result WriteTokenFile(string token)
    {
        try
        {
            var directory = Path.GetDirectoryName(_tokenPath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            File.WriteAllText(_tokenPath, PfctlOutput.RenderStoredToken(token));

            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(_tokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            return Result.Ok();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return Result.Fail(RulesetFileFailed(
                $"the PF enable reference could not be persisted to '{_tokenPath}': "
                + $"{ex.GetType().Name}: {ex.Message}"));
        }
    }

    private string? ReadStoredToken()
    {
        try
        {
            if (!File.Exists(_tokenPath))
            {
                return null;
            }

            return PfctlOutput.TryParseStoredToken(File.ReadAllText(_tokenPath), out var token)
                ? token
                : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static void DeleteFile(string path)
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
            // A leftover 0600 file in /tmp is harmless; a leftover token file is retried next run.
        }
    }

    private Task<CommandResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken) =>
        _runner.RunAsync(PfctlCommands.PfctlBinary, arguments, cancellationToken);

    private static string Describe(MyVpnError error) =>
        $"{error.Code}: {error.TechnicalDetail ?? error.MessageKey}";

    private static string Trim(string? value)
    {
        var text = (value ?? string.Empty)
            .Replace('\n', ' ')
            .Replace('\r', ' ')
            .Trim();

        return text.Length <= 300 ? text : text[..300] + "…";
    }

    private static bool DefaultElevationCheck()
    {
        if (!OperatingSystem.IsMacOS())
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
