using System.Diagnostics;

namespace MyVpn.Platform.Abstractions.Execution;

/// <summary>Outcome of a platform command.</summary>
public sealed record CommandResult(int ExitCode, string StandardOutput, string StandardError)
{
    public bool Succeeded => ExitCode == 0;

    /// <summary>Combined output, for logs and diagnostics.</summary>
    public string Combined =>
        string.IsNullOrWhiteSpace(StandardError) ? StandardOutput : $"{StandardOutput}\n{StandardError}".Trim();
}

/// <summary>
/// Runs external platform tools.
/// </summary>
/// <remarks>
/// <para>
/// <b>Arguments are always passed as a vector, never as a shell string.</b> Every one of these
/// commands eventually runs with elevated privileges, and a single interpolated value would turn
/// a configuration field into command execution. There is no <c>sh -c</c> anywhere in this
/// assembly, and there must never be one.
/// </para>
/// <para>
/// This is not hypothetical: the reference implementation this project studied builds a shell
/// script by concatenating values and runs it as root, with an <c>AppendQuotes</c> helper that
/// performs no escaping.
/// </para>
/// </remarks>
public interface ICommandRunner
{
    Task<CommandResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null);

    /// <summary>True when the executable exists on the PATH or at an absolute path.</summary>
    bool Exists(string fileName);
}

public sealed class ProcessCommandRunner : ICommandRunner
{
    private static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(20);

    public async Task<CommandResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken,
        TimeSpan? timeout = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(arguments);

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

        try
        {
            using var process = Process.Start(info);

            if (process is null)
            {
                return new CommandResult(-1, string.Empty, "the process could not be started");
            }

            var stdout = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var stderr = process.StandardError.ReadToEndAsync(cancellationToken);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutCts.CancelAfter(timeout ?? DefaultTimeout);

            try
            {
                await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
                {
                    // Best effort.
                }

                return new CommandResult(-1, string.Empty, $"'{fileName}' timed out");
            }

            return new CommandResult(
                process.ExitCode,
                await stdout.ConfigureAwait(false),
                await stderr.ConfigureAwait(false));
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return new CommandResult(-1, string.Empty, ex.Message);
        }
    }

    public bool Exists(string fileName)
    {
        if (string.IsNullOrWhiteSpace(fileName))
        {
            return false;
        }

        if (Path.IsPathRooted(fileName))
        {
            return File.Exists(fileName);
        }

        // Path.PathSeparator, not a hardcoded ':' -- on Windows the separator is ';' and a
        // Unix-only split would silently find nothing.
        foreach (var directory in (Environment.GetEnvironmentVariable("PATH") ?? string.Empty)
                     .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            if (File.Exists(Path.Combine(directory, fileName)))
            {
                return true;
            }
        }

        // A process started by a service or an elevated launcher frequently runs with a minimal
        // PATH, so the conventional locations are checked explicitly per platform.
        if (OperatingSystem.IsWindows())
        {
            var system32 = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System), fileName);

            return File.Exists(system32);
        }

        return File.Exists($"/usr/sbin/{fileName}")
               || File.Exists($"/usr/bin/{fileName}")
               || File.Exists($"/sbin/{fileName}")
               || File.Exists($"/bin/{fileName}")
               || File.Exists($"/sbin/{fileName}");
    }
}
