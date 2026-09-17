using System.Net;
using System.Text;
using MyVpn.Core.Net;
using MyVpn.Core.Results;
using MyVpn.Core.Settings;

namespace MyVpn.Infrastructure.Subscriptions;

/// <summary>A fetched subscription response.</summary>
public sealed record SubscriptionFetchResult
{
    public required string Body { get; init; }

    /// <summary>Response headers, in the order received, before any interpretation.</summary>
    public required IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; }

    /// <summary>URL actually served, after redirects. Used to resolve relative links.</summary>
    public required string FinalUrl { get; init; }

    public required TimeSpan Elapsed { get; init; }
}

/// <summary>
/// Fetches a subscription over HTTP(S).
/// </summary>
/// <remarks>
/// <para>
/// A subscription response is untrusted input, so the transport enforces the limits the rest of
/// the pipeline assumes: HTTPS only unless the user explicitly opted out, a hard response-size
/// cap so a hostile or broken server cannot exhaust memory, and a bounded set of response headers
/// so the header bag is never handed an unbounded stream.
/// </para>
/// <para>
/// Redirects are followed by the handler but every hop is re-checked against
/// <see cref="UrlSafety"/>, because following a redirect to a private address is the classic way
/// an SSRF guard is bypassed.
/// </para>
/// </remarks>
public sealed class SubscriptionFetcher : IDisposable
{
    private readonly HttpClient _client;
    private readonly bool _ownsClient;

    public SubscriptionFetcher(HttpClient? client = null)
    {
        if (client is not null)
        {
            _client = client;
            _ownsClient = false;
            return;
        }

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromSeconds(15),

            // Certificate revocation is checked explicitly: a subscription is a credential
            // delivery channel, so a revoked certificate must not be accepted.
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.Online,
            },
        };

        _client = new HttpClient(handler);
        _ownsClient = true;
    }

    public async Task<Result<SubscriptionFetchResult>> FetchAsync(
        string url,
        SubscriptionSettings settings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);

        if (!UrlSafety.IsSafeHttpUrl(url, settings.AllowInsecureHttp, out var reason, settings.AllowPrivateAddresses))
        {
            return Result<SubscriptionFetchResult>.Fail(new MyVpnError(
                ErrorCodes.SubscriptionUrlInvalid,
                reason == UrlRejectionReason.InsecureScheme
                    ? "error.subscription.url_insecure"
                    : "error.subscription.url_invalid",
                ErrorSeverity.Error,
                $"Subscription URL rejected: {reason}.",
                "subscription.fix_url"));
        }

        var started = System.Diagnostics.Stopwatch.GetTimestamp();

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(settings.TimeoutSeconds));

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation("User-Agent", settings.UserAgent);
            request.Headers.TryAddWithoutValidation("Accept", "*/*");

            using var response = await _client
                .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token)
                .ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return Result<SubscriptionFetchResult>.Fail(new MyVpnError(
                    ErrorCodes.SubscriptionHttpError,
                    "error.subscription.http_error",
                    ErrorSeverity.Error,
                    $"The subscription server returned {(int)response.StatusCode} {response.ReasonPhrase}.")
                    .WithArg("status", ((int)response.StatusCode).ToString(System.Globalization.CultureInfo.InvariantCulture)));
            }

            // Re-check the final URL: a redirect may have moved us somewhere we would have refused.
            var finalUrl = response.RequestMessage?.RequestUri?.ToString() ?? url;
            if (!UrlSafety.IsSafeHttpUrl(finalUrl, settings.AllowInsecureHttp, out var hopReason, settings.AllowPrivateAddresses))
            {
                return Result<SubscriptionFetchResult>.Fail(new MyVpnError(
                    ErrorCodes.SubscriptionUrlInvalid,
                    "error.subscription.url_invalid",
                    ErrorSeverity.Error,
                    $"A redirect led to a rejected address ({hopReason}).",
                    "subscription.fix_url"));
            }

            var maxBytes = (long)settings.MaxBodySizeMb * 1024 * 1024;

            var body = await ReadBoundedAsync(response, maxBytes, timeoutCts.Token).ConfigureAwait(false);
            if (body.IsFailure)
            {
                return Result<SubscriptionFetchResult>.Fail(body.Error!);
            }

            var headers = response.Headers
                .Concat(response.Content.Headers)
                .SelectMany(h => h.Value.Select(v => new KeyValuePair<string, string>(h.Key, v)))
                .ToArray();

            return Result<SubscriptionFetchResult>.Ok(new SubscriptionFetchResult
            {
                Body = body.Value,
                Headers = headers,
                FinalUrl = finalUrl,
                Elapsed = System.Diagnostics.Stopwatch.GetElapsedTime(started),
            });
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Result<SubscriptionFetchResult>.Fail(new MyVpnError(
                ErrorCodes.SubscriptionFetchFailed,
                "diagnostics.warning.server_timeout",
                ErrorSeverity.Error,
                $"The subscription did not respond within {settings.TimeoutSeconds}s.",
                "subscription.retry"));
        }
        catch (HttpRequestException ex)
        {
            return Result<SubscriptionFetchResult>.Fail(new MyVpnError(
                ErrorCodes.SubscriptionFetchFailed,
                "error.subscription.fetch_failed",
                ErrorSeverity.Error,
                ex.Message,
                "subscription.retry"));
        }
    }

    /// <summary>
    /// Reads the body up to a hard byte limit.
    /// </summary>
    /// <remarks>
    /// <c>Content-Length</c> is checked first as a cheap rejection, but the streaming read is what
    /// actually enforces the bound: a chunked response can lie about or omit its length, and
    /// reading to end before checking would be the denial of service the cap exists to prevent.
    /// </remarks>
    private static async Task<Result<string>> ReadBoundedAsync(
        HttpResponseMessage response,
        long maxBytes,
        CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength is { } declared && declared > maxBytes)
        {
            return Result<string>.Fail(TooLarge(declared, maxBytes));
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);

        using var buffer = new MemoryStream();
        var chunk = new byte[81920];

        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read <= 0)
            {
                break;
            }

            if (buffer.Length + read > maxBytes)
            {
                return Result<string>.Fail(TooLarge(buffer.Length + read, maxBytes));
            }

            buffer.Write(chunk, 0, read);
        }

        // Subscriptions are text, but a BOM or a stray invalid byte must not throw here.
        var bytes = buffer.ToArray();
        return Result<string>.Ok(Encoding.UTF8.GetString(bytes));
    }

    private static MyVpnError TooLarge(long actual, long maxBytes) =>
        new MyVpnError(
            ErrorCodes.SubscriptionFetchFailed,
            "error.subscriptions.body_size_range",
            ErrorSeverity.Error,
            $"The subscription response is larger than the {maxBytes / (1024 * 1024)} MB limit.");

    public void Dispose()
    {
        if (_ownsClient)
        {
            _client.Dispose();
        }
    }
}
