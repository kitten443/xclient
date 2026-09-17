using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace MyVpn.Rootless.Harness;

/// <summary>
/// Runs an external program with an explicit argv vector.
/// </summary>
/// <remarks>
/// There is no shell anywhere in this harness. Every command is a file name plus an argument
/// vector, so an interface name, a path or an address can never be re-interpreted as syntax —
/// the same rule the platform layer follows, applied to the test rig.
/// </remarks>
internal static class CommandRunner
{
    /// <summary>Absolute <c>ip</c>, matching the route manager's own preference, else the bare name.</summary>
    public static string IpBinary { get; } = File.Exists("/usr/sbin/ip") ? "/usr/sbin/ip" : "ip";

    public static async Task<CommandResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
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
            return new CommandResult(-1, string.Empty, $"'{fileName}' could not be started");
        }

        var stdout = process.StandardOutput.ReadToEndAsync(CancellationToken.None);
        var stderr = process.StandardError.ReadToEndAsync(CancellationToken.None);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        cts.CancelAfter(timeout);

        try
        {
            await process.WaitForExitAsync(cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            return new CommandResult(-1, string.Empty, $"'{fileName}' timed out after {timeout.TotalSeconds:0}s");
        }

        return new CommandResult(process.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
    }

    /// <summary>Runs a command and returns its trimmed standard output, or the error text.</summary>
    public static async Task<string> OutputAsync(string fileName, params string[] arguments)
    {
        var result = await RunAsync(fileName, arguments, TimeSpan.FromSeconds(10)).ConfigureAwait(false);
        return result.Succeeded
            ? result.StandardOutput.Trim()
            : $"<{fileName} exited {result.ExitCode}: {result.Combined.Trim()}>";
    }

    public static void TryKill(Process process)
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
            // Best effort: the process is on its way out either way.
        }
    }

    /// <summary>Renders an argv vector for the trace, quoting only what needs it.</summary>
    public static string Describe(string fileName, IReadOnlyList<string> arguments)
    {
        var builder = new StringBuilder(fileName);

        foreach (var argument in arguments)
        {
            builder.Append(' ').Append(
                argument.Length > 0 && argument.IndexOf(' ', StringComparison.Ordinal) < 0
                    ? argument
                    : $"'{argument}'");
        }

        return builder.ToString();
    }

    /// <summary>
    /// Counts running processes whose command line mentions <paramref name="needle"/>.
    /// </summary>
    /// <remarks>
    /// Used as the leak check. The throwaway root directory of a run is unique, and the core is
    /// started with a config path inside it, so any surviving process from that run — the helper
    /// itself, the far-side helper, the core on either side — is found by this one scan. A leaked
    /// namespace is kept alive precisely by such a process, so "no process mentions the run
    /// directory" is the same statement as "no namespace survived".
    /// </remarks>
    public static int CountProcessesReferencing(string needle)
    {
        var count = 0;

        foreach (var directory in Directory.EnumerateDirectories("/proc"))
        {
            var name = Path.GetFileName(directory);
            if (!int.TryParse(name, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
            {
                continue;
            }

            string commandLine;
            try
            {
                commandLine = File.ReadAllText(Path.Combine(directory, "cmdline"));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            if (commandLine.Contains(needle, StringComparison.Ordinal))
            {
                count++;
            }
        }

        return count;
    }
}

/// <summary>The outcome of one external command.</summary>
internal readonly record struct CommandResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;

    public string Combined => string.IsNullOrEmpty(StandardError)
        ? StandardOutput
        : string.IsNullOrEmpty(StandardOutput) ? StandardError : $"{StandardOutput}\n{StandardError}";

    public override string ToString() => $"exit={ExitCode} out={StandardOutput.Trim()} err={StandardError.Trim()}";
}
