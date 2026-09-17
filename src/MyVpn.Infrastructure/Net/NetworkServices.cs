using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using MyVpn.Application.Abstractions;
using MyVpn.Core.Domain;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;

namespace MyVpn.Infrastructure.Net;

/// <summary>
/// Resolves a profile's server address to IP literals.
/// </summary>
/// <remarks>
/// <para>
/// IPv4 results are returned first. A firewall rule and a route both need a concrete family, and
/// a dual-stack hostname would otherwise resolve to an IPv6 address on a network with no working
/// IPv6 — producing a tunnel that appears to connect and then carries nothing.
/// </para>
/// <para>
/// Hostname resolution here is deliberately a plain system lookup. It happens <i>before</i> any
/// tunnel exists, and it must not be routed through the tunnel, which would be circular.
/// </para>
/// </remarks>
public sealed class DnsServerEndpointResolver : IServerEndpointResolver
{
    public async Task<Result<IReadOnlyList<ServerEndpoint>>> ResolveAsync(
        ServerProfile profile,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(profile);

        // An IP literal needs no lookup, and skipping it avoids depending on the resolver for the
        // simplest and most robust kind of profile.
        if (IPAddress.TryParse(profile.Address, out var literal))
        {
            return Result<IReadOnlyList<ServerEndpoint>>.Ok(
                new[] { new ServerEndpoint(literal.ToString(), profile.Port) });
        }

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(profile.Address, cancellationToken)
                .ConfigureAwait(false);

            if (addresses.Length == 0)
            {
                return Result<IReadOnlyList<ServerEndpoint>>.Fail(NotResolved(profile.Address, "no addresses returned"));
            }

            var ordered = addresses
                .OrderBy(a => a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
                .Select(a => new ServerEndpoint(a.ToString(), profile.Port))
                .ToArray();

            return Result<IReadOnlyList<ServerEndpoint>>.Ok(ordered);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (SocketException ex)
        {
            return Result<IReadOnlyList<ServerEndpoint>>.Fail(
                NotResolved(profile.Address, ex.SocketErrorCode.ToString()));
        }
    }

    public async Task<string?> DescribeAsync(ServerEndpoint endpoint, CancellationToken cancellationToken)
    {
        if (!IPAddress.TryParse(endpoint.Address, out var address))
        {
            return null;
        }

        try
        {
            var entry = await Dns.GetHostEntryAsync(address.ToString(), cancellationToken).ConfigureAwait(false);
            return entry.HostName;
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            // Reverse lookup is cosmetic; failing it must never affect anything.
            return null;
        }
    }

    private static MyVpnError NotResolved(string host, string detail) =>
        new MyVpnError(
            ErrorCodes.KillSwitchApplyFailed,
            "error.killswitch.server_not_resolved",
            ErrorSeverity.Error,
            $"Could not resolve '{host}': {detail}. The Kill Switch cannot pin an address it "
            + "cannot resolve, so it must not be armed.",
            "diagnostics.check_dns")
        .WithArg("hosts", host);
}

/// <summary>
/// Verifies the tunnel by sending a real request through it.
/// </summary>
/// <remarks>
/// <para>
/// This is the check that distinguishes a working tunnel from a running process. In TUN mode the
/// core completes TCP handshakes locally and synthesises ICMP echo replies, so a successful
/// <c>connect()</c> or <c>ping</c> proves nothing. Only an end-to-end request does.
/// </para>
/// <para>
/// The request goes through the local HTTP inbound as a proxy, using a plain-HTTP endpoint so no
/// TLS stack is involved in the measurement itself. The address the endpoint reports is the
/// exit address, and comparing it with the host's own address is what catches a tunnel that is
/// up but not actually carrying anything.
/// </para>
/// </remarks>
public sealed class HttpProxyConnectionVerifier : IConnectionVerifier
{
    /// <summary>Plain-HTTP endpoint returning the caller's address as the whole body.</summary>
    public const string DefaultCheckEndpoint = "http://api.ipify.org/";

    private readonly string _checkEndpoint;

    public HttpProxyConnectionVerifier(string? checkEndpoint = null) =>
        _checkEndpoint = string.IsNullOrWhiteSpace(checkEndpoint) ? DefaultCheckEndpoint : checkEndpoint;

    public async Task<Result<ConnectionVerification>> VerifyAsync(
        TunnelMode mode,
        ProxySettings proxySettings,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(proxySettings);

        var started = System.Diagnostics.Stopwatch.GetTimestamp();

        // In TUN mode there is no local proxy to speak to: the operating system routes the request
        // into the tunnel, so a direct request IS the through-tunnel request.
        var throughProxy = mode == TunnelMode.SystemProxy;

        var exit = throughProxy
            ? await GetViaHttpProxyAsync(proxySettings, timeout, cancellationToken).ConfigureAwait(false)
            : await GetDirectAsync(timeout, cancellationToken).ConfigureAwait(false);

        if (exit.IsFailure)
        {
            return Result<ConnectionVerification>.Fail(
                exit.Error!.Code == ErrorCodes.OperationTimeout
                    ? exit.Error
                    : new MyVpnError(
                        ErrorCodes.XrayHealthCheckFailed,
                        "error.session.verification_failed",
                        ErrorSeverity.Error,
                        $"The tunnel did not carry a request to {_checkEndpoint}: {exit.Error.TechnicalDetail}",
                        "diagnostics.run"));
        }

        return Result<ConnectionVerification>.Ok(new ConnectionVerification
        {
            ExitAddress = exit.Value,
            Method = throughProxy
                ? $"HTTP proxy on 127.0.0.1:{proxySettings.EffectiveHttpPort}"
                : $"direct request ({mode})",
            Latency = System.Diagnostics.Stopwatch.GetElapsedTime(started),
        });
    }

    public async Task<string?> MeasureDirectAddressAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        var result = await GetDirectAsync(timeout, cancellationToken).ConfigureAwait(false);
        return result.IsSuccess ? result.Value : null;
    }

    private async Task<Result<string>> GetDirectAsync(TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            using var handler = new SocketsHttpHandler
            {
                // No proxy: this must measure the path the OS would take, which in TUN mode is the
                // tunnel and in system-proxy mode is the real network.
                UseProxy = false,
                ConnectTimeout = timeout,
            };

            using var client = new HttpClient(handler) { Timeout = timeout };

            var body = await client.GetStringAsync(_checkEndpoint, timeoutCts.Token).ConfigureAwait(false);
            var address = ParseAddress(body);

            return address is null
                ? Result<string>.Fail(Unreadable(body))
                : Result<string>.Ok(address);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Result<string>.Fail(Timeout(_checkEndpoint, timeout));
        }
        catch (HttpRequestException ex)
        {
            return Result<string>.Fail(Unreachable(_checkEndpoint, ex.Message));
        }
    }

    private async Task<Result<string>> GetViaHttpProxyAsync(
        ProxySettings proxySettings,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var port = proxySettings.EffectiveHttpPort;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(timeout);

        try
        {
            using var client = new TcpClient();

            await client.ConnectAsync(IPAddress.Loopback, port, timeoutCts.Token).ConfigureAwait(false);

            using var stream = client.GetStream();
            stream.ReadTimeout = (int)timeout.TotalMilliseconds;
            stream.WriteTimeout = (int)timeout.TotalMilliseconds;

            // Absolute-URI form, which is how a client addresses an origin through an HTTP proxy.
            var request =
                $"GET {_checkEndpoint} HTTP/1.1\r\n"
                + $"Host: {new Uri(_checkEndpoint).Authority}\r\n"
                + "User-Agent: MyVpn/0.1\r\n"
                + "Accept: */*\r\n"
                + "Connection: close\r\n\r\n";

            var requestBytes = Encoding.ASCII.GetBytes(request);
            await stream.WriteAsync(requestBytes, timeoutCts.Token).ConfigureAwait(false);
            await stream.FlushAsync(timeoutCts.Token).ConfigureAwait(false);

            using var buffer = new MemoryStream();
            var chunk = new byte[4096];

            while (true)
            {
                var read = await stream.ReadAsync(chunk, timeoutCts.Token).ConfigureAwait(false);
                if (read <= 0)
                {
                    break;
                }

                buffer.Write(chunk, 0, read);

                // The body is a bare address, so once the headers are in we have enough.
                if (buffer.Length > 8192)
                {
                    break;
                }
            }

            var response = Encoding.UTF8.GetString(buffer.ToArray());
            var separator = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);

            if (separator < 0)
            {
                return Result<string>.Fail(Unreadable(response));
            }

            var statusLine = response[..response.IndexOf("\r\n", StringComparison.Ordinal)];
            var body = response[(separator + 4)..].Trim();
            var address = ParseAddress(body);

            if (!statusLine.Contains(" 200", StringComparison.Ordinal) || address is null)
            {
                return Result<string>.Fail(Unreadable($"{statusLine} / {body}"));
            }

            return Result<string>.Ok(address);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Result<string>.Fail(Timeout($"127.0.0.1:{port}", timeout));
        }
        catch (SocketException ex)
        {
            // A refused connection here is the signature of "the core is running but its inbound
            // never came up", which is exactly the failure this check exists to catch.
            return Result<string>.Fail(Unreachable($"127.0.0.1:{port}", ex.SocketErrorCode.ToString()));
        }
    }

    /// <summary>Extracts an IP address from a response body, tolerating trailing newlines.</summary>
    private static string? ParseAddress(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
        {
            return null;
        }

        // Some endpoints return JSON; take the address-looking token either way.
        foreach (var token in body.Split(
                     new[] { ' ', '\n', '\r', '\t', '"', '{', '}', ':', ',' },
                     StringSplitOptions.RemoveEmptyEntries))
        {
            if (IPAddress.TryParse(token.Trim(), out var address))
            {
                return address.ToString();
            }
        }

        return null;
    }

    private static MyVpnError Timeout(string target, TimeSpan timeout) =>
        new MyVpnError(
            ErrorCodes.OperationTimeout,
            "diagnostics.warning.server_timeout",
            ErrorSeverity.Error,
            $"No response from {target} within {timeout.TotalSeconds.ToString("0.#", CultureInfo.InvariantCulture)}s.")
        .WithArg("timeout", timeout.TotalSeconds.ToString("0.#", CultureInfo.InvariantCulture));

    private static MyVpnError Unreachable(string target, string detail) =>
        new MyVpnError(
            ErrorCodes.XrayHealthCheckFailed,
            "error.session.verification_failed",
            ErrorSeverity.Error,
            $"{target} could not be reached: {detail}.");

    private static MyVpnError Unreadable(string? body) =>
        new MyVpnError(
            ErrorCodes.XrayHealthCheckFailed,
            "error.session.verification_failed",
            ErrorSeverity.Error,
            $"The check endpoint returned an unreadable response: '{Truncate(body)}'.");

    private static string Truncate(string? value) =>
        value is null ? string.Empty : value.Length <= 120 ? value : value[..120] + "…";
}
