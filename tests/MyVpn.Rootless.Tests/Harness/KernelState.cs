using System.Globalization;

namespace MyVpn.Rootless.Harness;

/// <summary>
/// Reads the kernel state this scenario cares about.
/// </summary>
/// <remarks>
/// Everything here is a read. The only writes in the whole harness happen during namespace setup
/// and through MyVpn's own executors, so a probe can never be the reason a test passes.
/// </remarks>
internal static class KernelState
{
    public static async Task<string> RouteGetAsync(string address)
    {
        var output = await CommandRunner.OutputAsync(CommandRunner.IpBinary, "-4", "route", "get", address)
            .ConfigureAwait(false);

        return FirstLine(output);
    }

    public static async Task<string> DefaultRouteAsync()
    {
        var output = await CommandRunner.OutputAsync(CommandRunner.IpBinary, "-4", "route", "show", "default")
            .ConfigureAwait(false);

        return Collapse(output);
    }

    public static async Task<string> LinkExistsAsync(string interfaceName)
    {
        var output = await CommandRunner.OutputAsync(CommandRunner.IpBinary, "link", "show", "dev", interfaceName)
            .ConfigureAwait(false);

        return output;
    }

    /// <summary>Interface names, with the <c>@peer</c> suffix <c>ip</c> prints for stacked devices removed.</summary>
    public static async Task<List<string>> InterfaceNamesAsync()
    {
        var output = await CommandRunner.OutputAsync(CommandRunner.IpBinary, "-brief", "link", "show")
            .ConfigureAwait(false);

        var names = new List<string>();

        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var token = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
            var at = token.IndexOf('@', StringComparison.Ordinal);
            names.Add(at > 0 ? token[..at] : token);
        }

        return names;
    }

    /// <summary>Interface addresses as <c>ip -brief address show</c> reports them.</summary>
    public static async Task<List<string>> AddressesAsync(string interfaceName)
    {
        var output = await CommandRunner.OutputAsync(
            CommandRunner.IpBinary, "-brief", "address", "show", "dev", interfaceName).ConfigureAwait(false);

        var addresses = new List<string>();
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        if (lines.Length == 0)
        {
            return addresses;
        }

        var tokens = lines[0].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);

        for (var index = 2; index < tokens.Length; index++)
        {
            addresses.Add(tokens[index]);
        }

        return addresses;
    }

    /// <summary>
    /// Contents of the MyVpn kill-switch table, or an empty string when it does not exist.
    /// </summary>
    /// <remarks>
    /// A missing table makes <c>nft</c> exit non-zero — that is the normal "not armed" answer, not
    /// an error, so it is reported as empty text rather than as a failure.
    /// </remarks>
    public static async Task<string> NftKillSwitchTableAsync()
    {
        var output = await CommandRunner.OutputAsync("nft", "list", "table", "inet", "myvpn_ks")
            .ConfigureAwait(false);

        return output.StartsWith('<') ? string.Empty : Collapse(output);
    }

    /// <summary>
    /// Counts live processes that are in <i>our</i> network namespace and run the given executable.
    /// </summary>
    /// <remarks>
    /// The namespace comparison is the point: the far side of the tunnel runs the very same core
    /// binary, so matching on the executable alone would count it and make the assertion
    /// meaningless. <c>/proc/&lt;pid&gt;/ns/net</c> is the kernel's own answer to "which namespace is
    /// this process in", so a process that survives a disconnect is found even if nothing else
    /// about it is known.
    /// </remarks>
    public static int CountProcessesInOurNamespaceRunning(string executablePath)
    {
        var ownNamespace = NamespaceLink("/proc/self/ns/net");
        var count = 0;

        foreach (var directory in Directory.EnumerateDirectories("/proc"))
        {
            var name = Path.GetFileName(directory);
            if (!int.TryParse(name, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
            {
                continue;
            }

            if (!string.Equals(NamespaceLink($"{directory}/ns/net"), ownNamespace, StringComparison.Ordinal))
            {
                continue;
            }

            var executable = NamespaceLink($"{directory}/exe");
            if (executable.Length == 0)
            {
                continue;
            }

            // A binary that was replaced under a running process reads back as "<path> (deleted)".
            var normalized = executable.EndsWith(" (deleted)", StringComparison.Ordinal)
                ? executable[..^" (deleted)".Length]
                : executable;

            if (string.Equals(normalized, executablePath, StringComparison.Ordinal))
            {
                count++;
            }
        }

        return count;
    }

    public static string ReadFileOrEmpty(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path).ReplaceLineEndings("\n").Trim() : string.Empty;
        }
        catch (IOException)
        {
            return string.Empty;
        }
    }

    private static string NamespaceLink(string path)
    {
        try
        {
            return File.ResolveLinkTarget(path, returnFinalTarget: false)?.FullName ?? string.Empty;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return string.Empty;
        }
    }

    private static string FirstLine(string text) =>
        text.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim() ?? string.Empty;

    private static string Collapse(string text) =>
        string.Join("\n", text.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => line.Trim()));
}
