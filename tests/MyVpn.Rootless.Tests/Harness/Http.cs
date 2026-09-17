using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace MyVpn.Rootless.Harness;

/// <summary>The result of one HTTP request made by the probe.</summary>
internal sealed record HttpProbeResult(
    int Status,
    string Body,
    double Milliseconds,
    double FirstByteMilliseconds,
    string? Error)
{
    public bool Succeeded => Status == 200;

    public override string ToString() => Status < 0
        ? $"no reply ({Error})"
        : $"HTTP {Status} in {Milliseconds:0} ms (first byte {FirstByteMilliseconds:0} ms): "
          + Body.ReplaceLineEndings(" ").Trim();
}

/// <summary>
/// A minimal HTTP/1.1 client that writes the request itself.
/// </summary>
/// <remarks>
/// <para>
/// Deliberately not <c>HttpClient</c>: a plain socket has no proxy discovery, no environment
/// handling and no connection reuse, so the only thing that can decide where the packet goes is
/// the kernel routing table — which is exactly what this harness is trying to observe. The
/// destination is always an IP literal, so no resolver is involved either.
/// </para>
/// <para>
/// Reading stops as soon as <c>Content-Length</c> bytes have arrived rather than at end of stream.
/// Waiting for the close would fold the peer's connection-teardown latency into the measurement and
/// report it as round-trip time.
/// </para>
/// </remarks>
internal static class HttpProbe
{
    public static async Task<HttpProbeResult> GetAsync(
        string address,
        int port,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        var started = DateTime.UtcNow;
        var firstByteAt = 0d;

        try
        {
            using var client = new TcpClient();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeout);

            await client.ConnectAsync(IPAddress.Parse(address), port, cts.Token).ConfigureAwait(false);

            var stream = client.GetStream();
            var request = string.Create(
                CultureInfo.InvariantCulture,
                $"GET / HTTP/1.1\r\nHost: {address}:{port}\r\nUser-Agent: myvpn-rootless-harness\r\nConnection: close\r\n\r\n");

            await stream.WriteAsync(Encoding.ASCII.GetBytes(request), cts.Token).ConfigureAwait(false);

            using var received = new MemoryStream();
            var buffer = new byte[4096];

            while (true)
            {
                int read;

                try
                {
                    read = await stream.ReadAsync(buffer, cts.Token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }

                if (read <= 0)
                {
                    break;
                }

                if (firstByteAt == 0)
                {
                    firstByteAt = (DateTime.UtcNow - started).TotalMilliseconds;
                }

                received.Write(buffer, 0, read);

                if (IsComplete(received))
                {
                    break;
                }
            }

            var elapsed = (DateTime.UtcNow - started).TotalMilliseconds;
            return Parse(Encoding.UTF8.GetString(received.ToArray()), elapsed, firstByteAt);
        }
        catch (Exception ex) when (ex is SocketException or IOException or OperationCanceledException
                                       or FormatException or ObjectDisposedException)
        {
            return new HttpProbeResult(
                -1,
                string.Empty,
                (DateTime.UtcNow - started).TotalMilliseconds,
                firstByteAt,
                $"{ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>True once the body the headers promised has arrived in full.</summary>
    private static bool IsComplete(MemoryStream received)
    {
        var text = Encoding.UTF8.GetString(received.GetBuffer(), 0, (int)received.Length);
        var separator = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);

        if (separator < 0)
        {
            return false;
        }

        var headerBlock = text[..separator];

        foreach (var line in headerBlock.Split("\r\n", StringSplitOptions.RemoveEmptyEntries))
        {
            if (!line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return int.TryParse(
                line["Content-Length:".Length..].Trim(),
                NumberStyles.Integer,
                CultureInfo.InvariantCulture,
                out var length)
                && Encoding.UTF8.GetByteCount(text[(separator + 4)..]) >= length;
        }

        // No length to go by: only the peer's close can end the body.
        return false;
    }

    private static HttpProbeResult Parse(string response, double milliseconds, double firstByteMilliseconds)
    {
        var separator = response.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var head = separator < 0 ? response : response[..separator];
        var body = separator < 0 ? string.Empty : response[(separator + 4)..];

        var status = -1;
        var firstLine = head.Split('\n')[0].Trim();
        var parts = firstLine.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length >= 2 && int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed))
        {
            status = parsed;
        }

        return new HttpProbeResult(
            status,
            body.Trim(),
            milliseconds,
            firstByteMilliseconds,
            status < 0 ? $"unparsable response: {firstLine}" : null);
    }
}

/// <summary>
/// The traffic target that lives on the far side of the tunnel.
/// </summary>
/// <remarks>
/// <para>
/// It answers every request with a body that names the <b>source address the kernel gave it</b>.
/// That one detail is what makes the end-to-end assertion meaningful: a direct request from the
/// client namespace arrives with the client's uplink address as its source, while a request that
/// came through the tunnel is dialled by the core on the far side and therefore arrives with the
/// target's own address. Reachability alone would prove nothing; the source proves the path.
/// </para>
/// <para>
/// It is a raw <see cref="TcpListener"/> rather than anything framework-shaped so that the fixture
/// has no dependency the environment might not have — no Python, no curl, no HTTP server package.
/// </para>
/// </remarks>
internal sealed class TargetServer : IAsyncDisposable
{
    private readonly TcpListener _listener;
    private readonly string _logPath;
    private readonly CancellationTokenSource _cts = new();
    private readonly List<string> _served = new();
    private readonly object _gate = new();
    private Task? _acceptLoop;

    public TargetServer(string address, int port, string logPath)
    {
        _listener = new TcpListener(IPAddress.Parse(address), port);
        _logPath = logPath;
        Address = address;
        Port = port;
    }

    public string Address { get; }

    public int Port { get; }

    /// <summary>Requests served so far, as <c>source -&gt; request line</c>.</summary>
    public IReadOnlyList<string> Served
    {
        get
        {
            lock (_gate)
            {
                return _served.ToArray();
            }
        }
    }

    public void Start()
    {
        _listener.Start();
        _acceptLoop = AcceptLoopAsync(_cts.Token);
    }

    public async ValueTask DisposeAsync()
    {
        await _cts.CancelAsync().ConfigureAwait(false);

        try
        {
            _listener.Stop();
        }
        catch (SocketException)
        {
            // Stopping an already-stopped listener is the desired end state.
        }

        if (_acceptLoop is not null)
        {
            try
            {
                await _acceptLoop.ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                // Expected during shutdown.
            }
        }

        _cts.Dispose();
    }

    private async Task AcceptLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                return;
            }

            _ = Task.Run(() => ServeAsync(client), CancellationToken.None);
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        var source = "unknown";

        try
        {
            source = client.Client.RemoteEndPoint is IPEndPoint endpoint
                ? endpoint.Address.ToString()
                : "unknown";

            var stream = client.GetStream();
            using var reader = new StreamReader(stream, Encoding.ASCII, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
            var requestLine = await reader.ReadLineAsync(CancellationToken.None).ConfigureAwait(false) ?? "(no request line)";

            var body = $"TARGET-OK from {source}\n";
            var response = string.Create(
                CultureInfo.InvariantCulture,
                $"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {Encoding.UTF8.GetByteCount(body)}\r\nConnection: close\r\n\r\n{body}");

            await stream.WriteAsync(Encoding.UTF8.GetBytes(response), CancellationToken.None).ConfigureAwait(false);
            await stream.FlushAsync(CancellationToken.None).ConfigureAwait(false);

            lock (_gate)
            {
                _served.Add($"{source} -> {requestLine}");
            }

            try
            {
                await File.AppendAllTextAsync(
                    _logPath,
                    string.Create(CultureInfo.InvariantCulture, $"{DateTime.UtcNow:O} {source} {requestLine}\n"),
                    CancellationToken.None).ConfigureAwait(false);
            }
            catch (IOException)
            {
                // The log is a convenience; the response body already carries the evidence.
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            lock (_gate)
            {
                _served.Add($"{source} -> (request failed: {ex.Message})");
            }
        }
        finally
        {
            client.Dispose();
        }
    }
}
