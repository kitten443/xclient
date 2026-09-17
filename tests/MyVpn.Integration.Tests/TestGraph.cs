using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using MyVpn.Application.Connection;
using MyVpn.Core.Domain;
using MyVpn.Core.Parsing;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;
using MyVpn.Core.Subscriptions;
using MyVpn.Infrastructure.App;
using MyVpn.Infrastructure.Geo;
using MyVpn.Infrastructure.Net;
using MyVpn.Infrastructure.Subscriptions;
using MyVpn.Infrastructure.Xray;

namespace MyVpn.Integration.Tests;

/// <summary>What a subscription fetch plus header and share-link parsing produced.</summary>
internal sealed record SubscriptionSelection(
    ServerProfile Profile,
    SubscriptionMetadata Metadata,
    string FinalUrl,
    int ProfileCount,
    int ParseFailureCount);

/// <summary>
/// Composes the real client pipeline against a throwaway filesystem and loopback endpoints.
/// </summary>
/// <remarks>
/// <para>
/// This is the same composition as <c>MyVpn.Cli.ConnectCommand</c> — a real
/// <see cref="VpnSession"/> with the real config store, core locator, core supervisor, geo
/// provider, endpoint resolver and HTTP-proxy verifier — but every path that would touch the
/// user's machine or the internet is redirected:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <see cref="AppPaths"/> gets a unique temp root, so the generated config, the geo working copy
/// and the manifest all live inside a directory this instance deletes on dispose. The seed
/// directory is passed explicitly rather than left to <c>MYVPN_GEO_SEED</c>, so a developer's
/// environment cannot change what the test proves.
/// </description></item>
/// <item><description>
/// A subscription is served by a loopback HTTP server on an ephemeral port. Fetching it is
/// subject to the SSRF guard, which is why the settings opt in explicitly (see
/// <see cref="PermissiveSubscriptions"/>).
/// </description></item>
/// <item><description>
/// The connection check endpoint is a loopback stand-in for <c>api.ipify.org</c>: it answers with
/// the peer address it observes. Every caller on this machine is seen as <c>127.0.0.1</c>, which
/// is exactly the honest situation the pipeline assertions describe — a loopback exit cannot be
/// distinguished from a direct connection.
/// </description></item>
/// <item><description>
/// No Kill Switch, system proxy, route or DNS executor is wired in. Those adapters change the
/// host's network state, and a test has no business doing that; with
/// <see cref="KillSwitchMode.Disabled"/> they are never consulted anyway, and system-proxy mode
/// reports a warning instead of pretending a desktop was reconfigured.
/// </description></item>
/// </list>
/// </remarks>
internal sealed class TestGraph : IDisposable
{
    private readonly string _root;
    private readonly List<LoopbackHttpServer> _subscriptionServers = new();
    private readonly LoopbackHttpServer _echo;
    private readonly XrayEngineManager _engine;
    private bool _disposed;

    private TestGraph(
        string root,
        AppPaths paths,
        AppSettings settings,
        XrayEngineManager engine,
        VpnSession session,
        LoopbackHttpServer echo,
        string? coreBinaryPath)
    {
        _root = root;
        _engine = engine;
        _echo = echo;
        Paths = paths;
        Settings = settings;
        Session = session;
        CoreBinaryPath = coreBinaryPath;
    }

    /// <summary>Temp-directory layout, deleted on dispose.</summary>
    public AppPaths Paths { get; }

    /// <summary>Settings that keep every side effect on the loopback interface.</summary>
    public AppSettings Settings { get; }

    public VpnSession Session { get; }

    public string? CoreBinaryPath { get; }

    /// <summary>
    /// Subscription settings that opt in to plain HTTP and to a loopback address.
    /// </summary>
    /// <remarks>
    /// Both opt-ins are deliberate. The SSRF guard refuses <c>http://127.0.0.1</c> by default
    /// because a subscription response is attacker-influenced input; this test is the legitimate
    /// self-hosted-on-the-same-machine case, and it says so explicitly instead of weakening the
    /// default. A companion test asserts the refusal still happens without the opt-in.
    /// </remarks>
    public SubscriptionSettings PermissiveSubscriptions => Settings.Subscriptions;

    /// <summary>The address the check endpoint reports for a caller on this machine.</summary>
    public string EchoAddress => _echo.Address;

    /// <summary>Composes the graph. <paramref name="coreBinaryPath"/> may be null for fetch-only tests.</summary>
    public static TestGraph Create(string? coreBinaryPath, string? seedGeoDataDirectory)
    {
        var root = Path.Combine(
            Path.GetTempPath(), "myvpn-loopback-graph", Guid.NewGuid().ToString("N"));

        var paths = new AppPaths(root, seedGeoDataDirectory);

        LoopbackHttpServer? echo = null;

        try
        {
            paths.EnsureCreated();

            // The HTTP inbound is always ListenPort + 1, so two adjacent ports are needed.
            var (socksPort, _) = LoopbackPort.FreePair("127.0.0.1");
            var settings = BuildSettings(socksPort);

            echo = LoopbackHttpServer.Start(
                "127.0.0.1",
                peer => peer?.Address.ToString() ?? "127.0.0.1");

            var loggerFactory = NullLoggerFactory.Instance;

            var geo = new GeoDataManager(
                new GeoDataOptions
                {
                    AssetDirectory = paths.GeoDataDirectory,
                    SeedDirectory = paths.SeedGeoDataDirectory,
                    BackupDirectory = paths.GeoBackupDirectory,
                    ManifestPath = paths.GeoManifestPath,
                },
                loggerFactory.CreateLogger<GeoDataManager>());

            // AutoRestart is off, exactly as in the CLI: a test that leaked a restart loop would
            // keep respawning cores after the assertions had already finished.
            var engine = new XrayEngineManager(
                loggerFactory.CreateLogger<XrayEngineManager>(),
                new XrayEngineOptions { AutoRestart = false });

            var session = new VpnSession(
                new VpnStateMachine(),
                paths,
                new AtomicConfigFileStore(),
                new CoreLocatorAdapter(engine),
                new CoreSupervisorAdapter(engine),
                new GeoDataProviderAdapter(geo),
                new DnsServerEndpointResolver(),
                new HttpProxyConnectionVerifier(echo.Url.ToString()),
                killSwitch: null,
                systemProxy: null,
                routes: null,
                dns: null,
                loggerFactory.CreateLogger<VpnSession>());

            return new TestGraph(root, paths, settings, engine, session, echo, coreBinaryPath);
        }
        catch
        {
            echo?.Dispose();
            TryDeleteDirectory(root);
            throw;
        }
    }

    /// <summary>Starts a loopback subscription server and returns its URL.</summary>
    /// <param name="body">Response body, i.e. the share links.</param>
    /// <param name="title">Optional <c>profile-title</c> header, to exercise header parsing.</param>
    public Uri ServeSubscription(string body, string? title = null)
    {
        var headers = title is null
            ? Array.Empty<KeyValuePair<string, string>>()
            : new[]
            {
                new KeyValuePair<string, string>(
                    "profile-title", "base64:" + Base64Tolerant.EncodeString(title)),
            };

        var server = LoopbackHttpServer.Start("127.0.0.1", _ => body, headers);
        _subscriptionServers.Add(server);

        return server.Url;
    }

    /// <summary>Fetches a subscription with the real fetch path, including the SSRF guard.</summary>
    public async Task<Result<SubscriptionFetchResult>> FetchAsync(
        Uri url,
        SubscriptionSettings settings,
        CancellationToken cancellationToken = default)
    {
        using var fetcher = new SubscriptionFetcher();

        return await fetcher.FetchAsync(url.ToString(), settings, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Fetch, then parse headers and share links exactly as <c>ConnectCommand</c> does.
    /// </summary>
    public async Task<Result<SubscriptionSelection>> SelectProfileAsync(
        Uri url,
        SubscriptionSettings settings,
        CancellationToken cancellationToken = default)
    {
        var fetched = await FetchAsync(url, settings, cancellationToken).ConfigureAwait(false);
        if (fetched.IsFailure)
        {
            return Result<SubscriptionSelection>.Fail(fetched.Error!);
        }

        var registry = SubscriptionHeaderRegistry.CreateDefault();
        var bag = registry.CreateBag(fetched.Value.Headers);
        var parsed = registry.Parse(new HeaderParseContext
        {
            Headers = bag,
            SubscriptionId = "loopback-test",
            SubscriptionUrl = new Uri(fetched.Value.FinalUrl),
            AllowInsecureHttp = settings.AllowInsecureHttp,
        });

        var batch = ShareLinkParser.ParseMany(fetched.Value.Body);
        if (batch.Profiles.Count == 0)
        {
            return Result<SubscriptionSelection>.Fail(new MyVpnError(
                ErrorCodes.SubscriptionFetchFailed,
                "error.subscription.no_profiles",
                ErrorSeverity.Error,
                "The loopback subscription contained no usable profiles."));
        }

        return Result<SubscriptionSelection>.Ok(new SubscriptionSelection(
            batch.Profiles[0],
            parsed.Metadata,
            fetched.Value.FinalUrl,
            batch.Profiles.Count,
            batch.Failures.Count));
    }

    /// <summary>A connect request bound to this graph's settings and core binary.</summary>
    public ConnectRequest Request(ServerProfile profile) => new()
    {
        Profile = profile,
        Settings = Settings,
        CoreBinaryPath = CoreBinaryPath,
    };

    /// <summary>The core's own last words, for failure messages.</summary>
    public IReadOnlyList<string> RecentCoreOutput(int maxLines) => _engine.GetRecentOutput(maxLines);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        foreach (var server in _subscriptionServers)
        {
            DisposeQuietly(server);
        }

        DisposeQuietly(_echo);

        // If a test failed between connect and disconnect this is what stops the core: the engine
        // kills the process tree on dispose. Teardown never depends on the test runner.
        DisposeQuietly(_engine);

        TryDeleteDirectory(_root);
    }

    private static AppSettings BuildSettings(int listenPort) => new()
    {
        // System-proxy mode is what the HTTP-proxy verifier measures: it sends the check request
        // to the local HTTP inbound. TUN mode would instead measure the machine's own routing.
        TunnelMode = TunnelMode.SystemProxy,

        // No elevation, so nothing to arm; the Kill Switch is never consulted.
        KillSwitch = KillSwitchMode.Disabled,

        Subscriptions = new SubscriptionSettings
        {
            // The two explicit opt-ins the SSRF guard requires for a loopback URL. See
            // PermissiveSubscriptions.
            AllowInsecureHttp = true,
            AllowPrivateAddresses = true,
        },

        Dns = new DnsSettings { Mode = DnsMode.ThroughTunnel },

        // LAN bypass must be OFF for this test. With it on, the generated routing sends
        // 127.0.0.0/8 (or geoip:private) to the `direct` outbound, so the check request would
        // never enter the tunnel at all and the test would prove nothing — and a tunnel pointing
        // at a closed port would appear to work.
        Routing = new RoutingSettings { BypassLan = false },

        Proxy = new ProxySettings { ListenPort = listenPort, EnableSocks = true, EnableHttp = true },
        Logging = new LoggingSettings { Verbosity = LogVerbosity.Warning },
    };

    private static void DisposeQuietly(IDisposable resource)
    {
        try
        {
            resource.Dispose();
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or InvalidOperationException)
        {
            // Cleanup runs in a finally; a failure here must not replace the real test failure.
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
}

/// <summary>
/// A minimal HTTP/1.1 server on the loopback interface, for subscriptions and for the
/// connection-check endpoint.
/// </summary>
/// <remarks>
/// Hand-rolled on <see cref="TcpListener"/> rather than using <c>HttpListener</c> because the
/// check endpoint has to answer with the <i>peer address it observed</i>, which is precisely what
/// makes the exit-address assertions meaningful. It binds port 0, so no test ever hardcodes a
/// port that a real service might already hold.
/// </remarks>
internal sealed class LoopbackHttpServer : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Func<IPEndPoint?, string> _body;
    private readonly IReadOnlyList<KeyValuePair<string, string>> _headers;
    private readonly Task _acceptLoop;
    private bool _disposed;

    private LoopbackHttpServer(
        TcpListener listener,
        string address,
        Func<IPEndPoint?, string> body,
        IReadOnlyList<KeyValuePair<string, string>> headers)
    {
        _listener = listener;
        _body = body;
        _headers = headers;
        Address = address;
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        Url = new Uri($"http://{address}:{Port}/");
        _acceptLoop = Task.Run(AcceptLoopAsync);
    }

    public string Address { get; }

    public int Port { get; }

    public Uri Url { get; }

    public static LoopbackHttpServer Start(
        string address,
        Func<IPEndPoint?, string> body,
        IReadOnlyList<KeyValuePair<string, string>>? headers = null)
    {
        ArgumentNullException.ThrowIfNull(body);

        var listener = new TcpListener(IPAddress.Parse(address), 0);
        listener.Start();

        return new LoopbackHttpServer(
            listener, address, body, headers ?? Array.Empty<KeyValuePair<string, string>>());
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;

        _cts.Cancel();
        _listener.Stop();

        try
        {
            // Bounded: a stuck connection handler must not hang teardown.
            _acceptLoop.Wait(TimeSpan.FromSeconds(2));
        }
        catch (Exception ex) when (ex is AggregateException or OperationCanceledException or ObjectDisposedException)
        {
            // The loop ends by cancellation or by the listener being closed; both are expected.
        }

        _cts.Dispose();
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;

            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException)
            {
                return;
            }

            _ = RespondAsync(client);
        }
    }

    private async Task RespondAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                var stream = client.GetStream();
                await ReadRequestHeadAsync(stream, _cts.Token).ConfigureAwait(false);

                var body = Encoding.UTF8.GetBytes(_body(client.Client.RemoteEndPoint as IPEndPoint));

                var head = new StringBuilder()
                    .Append("HTTP/1.1 200 OK\r\n")
                    .Append("Content-Type: text/plain; charset=utf-8\r\n")
                    .Append("Content-Length: ")
                    .Append(body.Length.ToString(CultureInfo.InvariantCulture))
                    .Append("\r\n")
                    .Append("Connection: close\r\n");

                foreach (var header in _headers)
                {
                    head.Append(header.Key).Append(": ").Append(header.Value).Append("\r\n");
                }

                head.Append("\r\n");

                await stream.WriteAsync(Encoding.ASCII.GetBytes(head.ToString()), _cts.Token)
                    .ConfigureAwait(false);
                await stream.WriteAsync(body, _cts.Token).ConfigureAwait(false);
                await stream.FlushAsync(_cts.Token).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
            {
                // A client that goes away mid-request is normal, and every server here is torn
                // down at the end of a test; neither is a test failure.
            }
        }
    }

    /// <summary>Reads the request head, bounded, since only the response body matters here.</summary>
    private static async Task ReadRequestHeadAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        var received = new StringBuilder();

        while (received.Length < 8192)
        {
            var read = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                return;
            }

            received.Append(Encoding.ASCII.GetString(buffer, 0, read));

            if (received.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
            {
                return;
            }
        }
    }
}
