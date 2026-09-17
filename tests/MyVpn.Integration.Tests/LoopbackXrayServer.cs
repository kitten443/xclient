using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace MyVpn.Integration.Tests;

/// <summary>
/// A real Xray server on the loopback interface, used as the far end of the whole client
/// pipeline.
/// </summary>
/// <remarks>
/// <para>
/// This is a genuine core process, not a stub: it speaks VLESS on a real TCP socket and forwards
/// what it receives through a <c>freedom</c> outbound. Plaintext VLESS is permitted here only
/// because the endpoint is a private address — the one situation in which there is nothing to
/// protect on the hop — and that is exactly what makes an end-to-end test possible with no VPN
/// server, no internet access and no privileges.
/// </para>
/// <para>
/// <b>Cleanup is not optional.</b> A leaked core keeps its inbound port bound and would break
/// every later run, so <see cref="Dispose"/> kills the process tree unconditionally, and the tests
/// hold the fixture in a <c>finally</c> rather than trusting the test runner to unwind.
/// </para>
/// </remarks>
internal sealed class LoopbackXrayServer : IDisposable
{
    /// <summary>How long the inbound is given to start listening before the fixture gives up.</summary>
    private static readonly TimeSpan StartupTimeout = TimeSpan.FromSeconds(20);

    private readonly Process _process;
    private readonly string _workingDirectory;
    private readonly StringBuilder _log;
    private readonly IPAddress _listenAddress;
    private bool _disposed;

    private LoopbackXrayServer(
        Process process,
        string workingDirectory,
        StringBuilder log,
        IPAddress listenAddress,
        int port,
        string userId)
    {
        _process = process;
        _workingDirectory = workingDirectory;
        _log = log;
        _listenAddress = listenAddress;
        Port = port;
        UserId = userId;
    }

    /// <summary>Address the VLESS inbound listens on, as it appears in the share link.</summary>
    public string ListenAddress => _listenAddress.ToString();

    /// <summary>Ephemeral port the VLESS inbound listens on.</summary>
    public int Port { get; }

    /// <summary>UUID the inbound accepts; it is also the client's user id.</summary>
    public string UserId { get; }

    /// <summary>Share link for this server, in the exact form a subscription would carry.</summary>
    public string ShareLink =>
        $"vless://{UserId}@{ListenAddress}:{Port}?encryption=none&type=tcp&security=none#Loopback%20Server";

    /// <summary>Everything the core has printed, for failure messages.</summary>
    public string Log
    {
        get
        {
            lock (_log)
            {
                return _log.ToString();
            }
        }
    }

    /// <summary>The live process id, so a test can prove it is gone after disconnect.</summary>
    public int ProcessId => _process.Id;

    /// <summary>
    /// Writes a server config, starts the core and waits until the inbound actually accepts.
    /// </summary>
    /// <param name="binaryPath">Absolute path to the Xray binary.</param>
    /// <param name="listenAddress">
    /// Loopback address to bind. The tests deliberately use an address that is <i>not</i> the one
    /// the verification endpoint reports, so that the client's "the exit address equals the direct
    /// address" warning is observable at all; see <c>LoopbackPipelineTests</c>.
    /// </param>
    /// <param name="userId">UUID the inbound accepts.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    public static async Task<LoopbackXrayServer> StartAsync(
        string binaryPath,
        string listenAddress,
        string userId,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(binaryPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(listenAddress);
        ArgumentException.ThrowIfNullOrWhiteSpace(userId);

        var address = IPAddress.Parse(listenAddress);
        var port = LoopbackPort.Free(listenAddress);
        var workingDirectory = Path.Combine(
            Path.GetTempPath(), "myvpn-loopback-server", Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(workingDirectory);
        var configPath = Path.Combine(workingDirectory, "server-config.json");
        await File.WriteAllTextAsync(configPath, BuildConfig(listenAddress, port, userId), cancellationToken)
            .ConfigureAwait(false);

        var info = new ProcessStartInfo
        {
            FileName = binaryPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = workingDirectory,
        };

        info.ArgumentList.Add("run");
        info.ArgumentList.Add("-c");
        info.ArgumentList.Add(configPath);

        var log = new StringBuilder();
        var process = new Process { StartInfo = info, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, args) => Append(log, args.Data);
        process.ErrorDataReceived += (_, args) => Append(log, args.Data);

        try
        {
            if (!process.Start())
            {
                throw new InvalidOperationException(
                    $"Could not start the loopback Xray server at '{binaryPath}'.");
            }
        }
        catch
        {
            process.Dispose();
            TryDeleteDirectory(workingDirectory);
            throw;
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        var server = new LoopbackXrayServer(process, workingDirectory, log, address, port, userId);

        try
        {
            await server.WaitForInboundAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Never leave a half-started core behind: the caller never sees this instance, so it
            // could not dispose it.
            server.Dispose();
            throw;
        }

        return server;
    }

    /// <summary>
    /// Locates the local core under <c>.tools/xray</c>, or explains why the test must be skipped.
    /// </summary>
    /// <remarks>
    /// <c>.tools/</c> is gitignored, so on a clean checkout the core is simply absent. That is a
    /// missing prerequisite, not a defect, so the tests report a skip with this reason instead of
    /// failing.
    /// </remarks>
    public static bool TryLocateCoreBinary(out string binaryPath, out string reason)
    {
        binaryPath = string.Empty;

        if (!OperatingSystem.IsLinux())
        {
            reason = $"the loopback pipeline test drives a native Xray core and currently runs on "
                     + $"Linux only (this host is {RuntimeInformationDescription()}).";
            return false;
        }

        var root = FindRepositoryRoot();
        if (root is null)
        {
            reason = "could not locate the repository root (a directory containing MyVpn.sln) from "
                     + $"'{AppContext.BaseDirectory}' or '{Directory.GetCurrentDirectory()}'.";
            return false;
        }

        var candidate = Path.Combine(root, ".tools", "xray", "xray");

        if (!File.Exists(candidate))
        {
            reason = $"no Xray core at '{candidate}'. '.tools/' is gitignored, so a clean checkout "
                     + "does not have one; restore it to run this test.";
            return false;
        }

        if (!MyVpn.Infrastructure.Xray.XrayBinaryLocator.IsExecutableOnUnix(candidate))
        {
            reason = $"the Xray core at '{candidate}' is not executable.";
            return false;
        }

        binaryPath = candidate;
        reason = string.Empty;
        return true;
    }

    /// <summary>
    /// Locates the real <c>geoip.dat</c>/<c>geosite.dat</c> shipped beside the local core.
    /// </summary>
    /// <remarks>
    /// The geo-seeding assertion needs real assets: <c>EnsureWorkingCopyAsync</c> validates what
    /// it copies, so a synthetic or truncated file would change what the test proves.
    /// </remarks>
    public static bool TryLocateSeedGeoData(out string directory, out string reason)
    {
        directory = string.Empty;

        if (!TryLocateCoreBinary(out var binaryPath, out reason))
        {
            return false;
        }

        var assets = Path.GetDirectoryName(binaryPath)!;
        foreach (var name in new[] { "geoip.dat", "geosite.dat" })
        {
            var path = Path.Combine(assets, name);
            if (!File.Exists(path))
            {
                reason = $"no '{path}'. The geo-seeding assertion needs the real asset files that "
                         + "ship beside the local core.";
                return false;
            }
        }

        directory = assets;
        reason = string.Empty;
        return true;
    }

    /// <summary>Walks up from the test output directory until it finds the repository root.</summary>
    private static string? FindRepositoryRoot()
    {
        foreach (var start in new[] { AppContext.BaseDirectory, Directory.GetCurrentDirectory() })
        {
            var directory = new DirectoryInfo(start);

            while (directory is not null)
            {
                if (File.Exists(Path.Combine(directory.FullName, "MyVpn.sln")))
                {
                    return directory.FullName;
                }

                directory = directory.Parent;
            }
        }

        return null;
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);

                // Wait for the exit so the inbound port is released before the next test binds it.
                _process.WaitForExit(5000);
            }
        }
        catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
        {
            // Best effort: the fixture is being torn down, and a second kill attempt would fail
            // for the same reason.
        }
        finally
        {
            _process.Dispose();
            TryDeleteDirectory(_workingDirectory);
        }
    }

    private async Task WaitForInboundAsync(CancellationToken cancellationToken)
    {
        var deadline = DateTime.UtcNow + StartupTimeout;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_process.HasExited)
            {
                throw new InvalidOperationException(
                    $"The loopback Xray server exited with code {_process.ExitCode} before its "
                    + $"inbound opened on {ListenAddress}:{Port}.{Environment.NewLine}{Log}");
            }

            try
            {
                using var probe = new TcpClient();
                await probe.ConnectAsync(_listenAddress, Port, cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (SocketException)
            {
                // Not listening yet.
            }

            await Task.Delay(100, cancellationToken).ConfigureAwait(false);
        }

        throw new TimeoutException(
            $"The loopback Xray server did not open {ListenAddress}:{Port} within "
            + $"{StartupTimeout.TotalSeconds.ToString("0.#", CultureInfo.InvariantCulture)}s."
            + $"{Environment.NewLine}{Log}");
    }

    /// <summary>Builds the smallest server config that can carry traffic: VLESS in, freedom out.</summary>
    /// <remarks>
    /// <para>
    /// The <c>finalRules</c> entry is not decoration. Current Xray applies a server-side safety
    /// policy to the <c>freedom</c> outbound: traffic that arrived from a VLESS inbound is blocked
    /// by default when it targets a private or reserved address, and a blocked target is
    /// blackholed for 30-90 seconds rather than refused. A loopback destination is private by
    /// definition, so without this explicit <c>allow</c> rule the server accepts the tunnel and
    /// then silently drops everything — the failure mode is "the core is up but carries nothing",
    /// which is precisely what this fixture hit when it was first written.
    /// </para>
    /// <para>
    /// The rule is scoped to loopback, so the core's default protection remains in force for every
    /// other private range: the test needs to reach the machine it is already running on, not to
    /// disable an SSRF guard.
    /// </para>
    /// </remarks>
    private static string BuildConfig(string listenAddress, int port, string userId)
    {
        var portText = port.ToString(CultureInfo.InvariantCulture);

        return $$"""
        {
          "log": { "loglevel": "warning" },
          "inbounds": [
            {
              "tag": "vless-in",
              "listen": "{{listenAddress}}",
              "port": {{portText}},
              "protocol": "vless",
              "settings": {
                "clients": [ { "id": "{{userId}}", "email": "loopback@myvpn.test" } ],
                "decryption": "none"
              },
              "streamSettings": { "network": "tcp", "security": "none" }
            }
          ],
          "outbounds": [
            {
              "tag": "freedom",
              "protocol": "freedom",
              "settings": {
                "finalRules": [
                  { "action": "allow", "ip": ["127.0.0.0/8", "::1/128"] }
                ]
              }
            }
          ]
        }
        """;
    }

    private static void Append(StringBuilder log, string? line)
    {
        if (line is null)
        {
            return;
        }

        lock (log)
        {
            log.AppendLine(line);
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }

            // The unique directory lives under a shared container. Removing the container when it
            // is empty leaves nothing at all behind; a concurrent test that still owns an entry
            // makes this fail harmlessly.
            var parent = Path.GetDirectoryName(path);
            if (parent is not null
                && Directory.Exists(parent)
                && !Directory.EnumerateFileSystemEntries(parent).Any())
            {
                Directory.Delete(parent);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Test cleanup is best effort.
        }
    }

    private static string RuntimeInformationDescription() =>
        System.Runtime.InteropServices.RuntimeInformation.OSDescription;
}

/// <summary>
/// Ephemeral-port discovery for the loopback fixtures.
/// </summary>
/// <remarks>
/// Nothing here may hardcode a port: a fixed port collides with a real service on a developer
/// machine, and a leaked core from an earlier run would then make every later run fail. A port
/// discovered by binding port 0 can still be claimed by another process in the window between
/// release and use, which is inherent to discovering ports this way and is why the tests also
/// verify the pipeline end to end rather than assuming the bind succeeded.
/// </remarks>
internal static class LoopbackPort
{
    /// <summary>Binds port 0, reads the port the kernel chose, and releases it.</summary>
    public static int Free(string address)
    {
        var listener = new TcpListener(IPAddress.Parse(address), 0);
        listener.Start();

        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// Finds two adjacent free ports.
    /// </summary>
    /// <remarks>
    /// The client's HTTP inbound is always <c>ListenPort + 1</c> (it is derived in
    /// <c>ProxySettings</c> so the config builder and the verifier cannot disagree), so the two
    /// have to be free together.
    /// </remarks>
    public static (int Socks, int Http) FreePair(string address)
    {
        for (var attempt = 0; attempt < 32; attempt++)
        {
            var first = Free(address);

            // Ports below 1024 need privileges and ListenPort + 1 must not overflow.
            if (first is < 1024 or > 65534)
            {
                continue;
            }

            if (IsFree(address, first + 1))
            {
                return (first, first + 1);
            }
        }

        throw new InvalidOperationException($"Could not find two adjacent free TCP ports on {address}.");
    }

    /// <summary>True when a listener can be bound to the port right now.</summary>
    public static bool IsFree(string address, int port)
    {
        if (port is < 1 or > 65535)
        {
            return false;
        }

        var listener = new TcpListener(IPAddress.Parse(address), port);

        try
        {
            listener.Start();
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// Waits, bounded, for a port to become bindable again after the core has been stopped.
    /// </summary>
    public static async Task<bool> WaitUntilFreeAsync(string address, int port, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;

        do
        {
            if (IsFree(address, port))
            {
                return true;
            }

            await Task.Delay(50).ConfigureAwait(false);
        }
        while (DateTime.UtcNow < deadline);

        return IsFree(address, port);
    }
}
