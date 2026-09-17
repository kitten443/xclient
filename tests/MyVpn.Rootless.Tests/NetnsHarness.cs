using System.Diagnostics;
using System.Globalization;
using System.Text;
using System.Text.Json;
using MyVpn.Rootless.Harness;
using Xunit.Abstractions;

namespace MyVpn.Rootless.Tests;

/// <summary>One completed run: what the namespace reported, plus what the host looks like now.</summary>
internal sealed record ScenarioRun(
    RootlessReport Report,
    string WorkDirectory,
    IReadOnlyList<string> StdErrLines,
    IReadOnlyList<string> HostInterfaces,
    int ProcessesReferencingRun,
    string HostDefaultRoute);

/// <summary>
/// Starts the harness inside a throwaway user, mount and network namespace and reads its report.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why a namespace and not <c>sudo</c>.</b> <c>unshare -rmn</c> maps the calling user to root
/// inside a new user namespace and gives that root <c>CAP_NET_ADMIN</c> over a brand-new network
/// namespace. Everything the tunnel needs — creating a TUN device, assigning addresses, replacing
/// the default route, loading an nftables ruleset — is therefore permitted, while the host's
/// interfaces, routes and firewall live in a different network namespace and are not reachable at
/// all. No privilege is required on the host, nothing survives the last process, and a mistake can
/// only ever break the sandbox.
/// </para>
/// <para>
/// The mount namespace is taken for the same reason (see the DNS note in
/// <see cref="ClientScenario"/>), and made private so that nothing done inside can propagate out.
/// </para>
/// </remarks>
internal static class NetnsHarness
{
    /// <summary>How long a whole scenario may take before the rig is declared stuck.</summary>
    private static readonly TimeSpan RunTimeout = TimeSpan.FromSeconds(180);

    /// <summary>
    /// Checks that this machine can host the scenario at all.
    /// </summary>
    /// <remarks>
    /// Every condition is reported, never thrown: a machine without user namespaces, without
    /// <c>/dev/net/tun</c>, or without the (git-ignored) core binary is a place where this test is
    /// simply not applicable, and the suite must stay green there. Following the pattern already
    /// used by <c>NftablesKillSwitchRendererTests</c>, the test returns early with the reason
    /// printed rather than failing.
    /// </remarks>
    public static bool TryPrepare(ITestOutputHelper output, bool requiresNft, out string reason)
    {
        ArgumentNullException.ThrowIfNull(output);

        if (!File.Exists("/dev/net/tun"))
        {
            reason = "/dev/net/tun does not exist, so no TUN device can be created.";
            output.WriteLine($"SKIPPED: {reason}");
            return false;
        }

        if (!TryFindRepoRoot(out var repoRoot))
        {
            reason = "the repository root could not be located from the test output directory.";
            output.WriteLine($"SKIPPED: {reason}");
            return false;
        }

        var xray = Path.Combine(repoRoot, ".tools", "xray", "xray");
        if (!File.Exists(xray))
        {
            reason = $"{xray} is absent (.tools/ is not committed), so there is no core to drive.";
            output.WriteLine($"SKIPPED: {reason}");
            return false;
        }

        if (!File.Exists("/usr/bin/unshare") && !File.Exists("/bin/unshare"))
        {
            reason = "unshare is not installed.";
            output.WriteLine($"SKIPPED: {reason}");
            return false;
        }

        if (requiresNft && !File.Exists("/usr/sbin/nft") && !File.Exists("/usr/bin/nft"))
        {
            reason = "nft is not installed, so the Kill Switch cannot be exercised.";
            output.WriteLine($"SKIPPED: {reason}");
            return false;
        }

        if (FindDotnet() is null)
        {
            reason = "no dotnet host could be located to start the harness with.";
            output.WriteLine($"SKIPPED: {reason}");
            return false;
        }

        if (!TryFindHarnessAssembly(out _))
        {
            reason = "the harness assembly has not been built next to this test project.";
            output.WriteLine($"SKIPPED: {reason}");
            return false;
        }

        // The probe that matters: whether this environment actually grants the capabilities the
        // scenario needs. This is exactly the operation the harness performs, so its exit code is
        // the answer, and a policy that disables unprivileged user namespaces shows up here as a
        // skip rather than as a confusing failure several seconds later.
        var probe = RunCommand("unshare", new[] { "-rmn", "--propagation", "private", "true" }, TimeSpan.FromSeconds(20));
        if (probe.ExitCode != 0)
        {
            reason = $"'unshare -rmn --propagation private true' failed: {probe.Combined.Trim()}";
            output.WriteLine($"SKIPPED: {reason}");
            return false;
        }

        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Runs the scenario and returns everything the test needs to judge it.
    /// </summary>
    /// <exception cref="InvalidOperationException">The rig itself failed; that is a test bug, not a skip.</exception>
    public static async Task<ScenarioRun> RunAsync(ITestOutputHelper output, string killSwitchMode)
    {
        ArgumentNullException.ThrowIfNull(output);

        if (!TryFindRepoRoot(out var repoRoot)
            || !TryFindHarnessAssembly(out var harness)
            || FindDotnet() is not { } detected)
        {
            throw new InvalidOperationException("the harness rig is not available; TryPrepare should have skipped");
        }

        var xray = Path.Combine(repoRoot, ".tools", "xray", "xray");
        var work = Path.Combine(
            Path.GetTempPath(),
            string.Create(CultureInfo.InvariantCulture, $"myvpn-rootless-{Guid.NewGuid():N}"));

        Directory.CreateDirectory(work);

        Process? process = null;

        try
        {
            var info = new ProcessStartInfo
            {
                FileName = File.Exists("/usr/bin/unshare") ? "/usr/bin/unshare" : "unshare",
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = work,
            };

            foreach (var argument in new[]
            {
                "-rmn", "--propagation", "private",
                detected, harness, HarnessArgs.ClientRole,
                "--work", work,
                "--xray", xray,
                "--user-id", "7e5f1a2c-9d4b-4a6e-8f31-0c2b5d7e9a13",
                "--server-port", "8443",
                "--kill-switch", killSwitchMode,
                "--dotnet", detected,
                "--harness", harness,
            })
            {
                info.ArgumentList.Add(argument);
            }

            output.WriteLine($"running: {Describe(info)}");
            output.WriteLine($"work dir: {work}");

            process = Process.Start(info) ?? throw new InvalidOperationException("could not start unshare");

            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            var stdoutDone = ReadIntoAsync(process.StandardOutput, stdout);
            var stderrDone = ReadIntoAsync(process.StandardError, stderr);

            var exit = await WaitForExitAsync(process, RunTimeout).ConfigureAwait(false);

            if (!exit)
            {
                Kill(process);
                throw new InvalidOperationException(
                    $"the harness did not finish within {RunTimeout.TotalSeconds:0}s. stderr: {stderr}");
            }

            // Drain the readers before touching the report: output written just before exit can
            // still be in flight.
            await Task.WhenAll(stdoutDone, stderrDone).WaitAsync(TimeSpan.FromSeconds(10)).ConfigureAwait(false);

            var reportPath = Path.Combine(work, "report.json");
            if (!File.Exists(reportPath))
            {
                throw new InvalidOperationException(
                    $"the harness wrote no report (exit {process.ExitCode}). stderr: {stderr}");
            }

            var report = JsonSerializer.Deserialize<RootlessReport>(await File.ReadAllTextAsync(reportPath).ConfigureAwait(false))
                ?? throw new InvalidOperationException($"'{reportPath}' deserialised to null");

            output.WriteLine($"harness exit code: {process.ExitCode}");

            foreach (var line in report.Trace)
            {
                output.WriteLine($"  | {line}");
            }

            foreach (var line in SplitLines(stderr.ToString()))
            {
                output.WriteLine($"  ! {line}");
            }

            // Host-side teardown evidence, gathered after the run has ended: anything still present
            // here is a leak.
            var result = new ScenarioRun(
                report,
                work,
                SplitLines(stderr.ToString()),
                HostInterfaces(),
                CountProcessesReferencing(work),
                HostDefaultRoute());

            Kill(process);
            process.Dispose();
            process = null;

            return result;
        }
        finally
        {
            if (process is not null)
            {
                Kill(process);
                process.Dispose();
            }

            TryDelete(work);
        }
    }

    /// <summary>Interface names on the host itself, which this design must never change.</summary>
    public static IReadOnlyList<string> HostInterfaces()
    {
        var result = RunCommand("/usr/sbin/ip", new[] { "-brief", "link", "show" }, TimeSpan.FromSeconds(15));

        if (result.ExitCode != 0)
        {
            result = RunCommand("ip", new[] { "-brief", "link", "show" }, TimeSpan.FromSeconds(15));
        }

        return SplitLines(result.StandardOutput)
            .Select(line => line.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0])
            .Select(name => name.Contains('@', StringComparison.Ordinal)
                ? name[..name.IndexOf('@', StringComparison.Ordinal)]
                : name)
            .ToArray();
    }

    public static string HostDefaultRoute()
    {
        var result = RunCommand("/usr/sbin/ip", new[] { "-4", "route", "show", "default" }, TimeSpan.FromSeconds(15));

        if (result.ExitCode != 0)
        {
            result = RunCommand("ip", new[] { "-4", "route", "show", "default" }, TimeSpan.FromSeconds(15));
        }

        return result.StandardOutput.Trim();
    }

    /// <summary>
    /// Counts processes whose command line mentions the run's directory.
    /// </summary>
    /// <remarks>
    /// The directory is unique per run, and every process the run starts carries it: the helper,
    /// the far-side helper, and both cores (their config paths live inside it). A process still
    /// matching after the run is a leaked process, and a leaked process is exactly what would keep
    /// a namespace alive — so this is the host-visible half of the "nothing is left behind" claim.
    /// </remarks>
    public static int CountProcessesReferencing(string workDirectory)
    {
        var count = 0;

        foreach (var directory in Directory.EnumerateDirectories("/proc"))
        {
            if (!int.TryParse(Path.GetFileName(directory), NumberStyles.Integer, CultureInfo.InvariantCulture, out var pid)
                || pid == Environment.ProcessId)
            {
                continue;
            }

            try
            {
                if (File.ReadAllText(Path.Combine(directory, "cmdline")).Contains(workDirectory, StringComparison.Ordinal))
                {
                    count++;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                // A process that exited while being inspected is not a leak.
            }
        }

        return count;
    }

    private static async Task<bool> WaitForExitAsync(Process process, TimeSpan timeout)
    {
        using var cancellation = new CancellationTokenSource(timeout);

        try
        {
            await process.WaitForExitAsync(cancellation.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private static async Task ReadIntoAsync(StreamReader reader, StringBuilder sink)
    {
        var buffer = new char[4096];

        while (true)
        {
            var read = await reader.ReadAsync(buffer).ConfigureAwait(false);
            if (read <= 0)
            {
                return;
            }

            sink.Append(buffer, 0, read);
        }
    }

    private static void Kill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or SystemException)
        {
            // Best effort: the namespace dies with its last process either way.
        }
    }

    private static void TryDelete(string directory)
    {
        try
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Leftovers live in the temp directory and are inert.
        }
    }

    private static IReadOnlyList<string> SplitLines(string text) =>
        text.ReplaceLineEndings("\n")
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(line => line.TrimEnd())
            .ToArray();

    private static string Describe(ProcessStartInfo info) =>
        info.FileName + " " + string.Join(' ', info.ArgumentList);

    private static bool TryFindRepoRoot(out string root)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        while (directory is not null)
        {
            if (File.Exists(Path.Combine(directory.FullName, "MyVpn.sln")))
            {
                root = directory.FullName;
                return true;
            }

            directory = directory.Parent;
        }

        root = string.Empty;
        return false;
    }

    private static bool TryFindHarnessAssembly(out string path)
    {
        path = string.Empty;

        if (!TryFindRepoRoot(out var root))
        {
            return false;
        }

        var configuration = AppContext.BaseDirectory.Contains("/Release/", StringComparison.Ordinal)
            ? "Release"
            : "Debug";

        var candidate = Path.Combine(
            root, "tests", "MyVpn.Rootless.Tests", "Harness", "bin", configuration, "net8.0",
            "MyVpn.Rootless.Harness.dll");

        if (!File.Exists(candidate))
        {
            return false;
        }

        path = candidate;
        return true;
    }

    private static string? FindDotnet()
    {
        var candidates = new[]
        {
            Environment.GetEnvironmentVariable("DOTNET_HOST_PATH"),
            Environment.ProcessPath is { } running && Path.GetFileNameWithoutExtension(running) == "dotnet"
                ? running
                : null,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".dotnet", "dotnet"),
            "/usr/bin/dotnet",
            "/usr/share/dotnet/dotnet",
        };

        return candidates.FirstOrDefault(candidate => !string.IsNullOrEmpty(candidate) && File.Exists(candidate));
    }

    private static CommandLineResult RunCommand(string fileName, string[] arguments, TimeSpan timeout)
    {
        try
        {
            var info = new ProcessStartInfo
            {
                FileName = fileName,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            foreach (var argument in arguments)
            {
                info.ArgumentList.Add(argument);
            }

            using var process = Process.Start(info);
            if (process is null)
            {
                return new CommandLineResult(-1, string.Empty, $"'{fileName}' could not be started");
            }

            var stdout = process.StandardOutput.ReadToEnd();
            var stderr = process.StandardError.ReadToEnd();

            return process.WaitForExit((int)timeout.TotalMilliseconds)
                ? new CommandLineResult(process.ExitCode, stdout, stderr)
                : new CommandLineResult(-1, stdout, $"'{fileName}' timed out");
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new CommandLineResult(-1, string.Empty, ex.Message);
        }
    }

    private readonly record struct CommandLineResult(int ExitCode, string StandardOutput, string StandardError)
    {
        public string Combined => string.IsNullOrEmpty(StandardError)
            ? StandardOutput
            : string.IsNullOrEmpty(StandardOutput) ? StandardError : $"{StandardOutput}\n{StandardError}";
    }
}
