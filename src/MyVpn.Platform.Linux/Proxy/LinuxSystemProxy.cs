using System.Globalization;
using System.Text;
using MyVpn.Core.Results;
using MyVpn.Platform.Abstractions.Proxy;
using MyVpn.Platform.Abstractions.Execution;

namespace MyVpn.Platform.Linux.Proxy;

/// <summary>
/// Configures the desktop proxy through <c>gsettings</c> (GNOME/GSettings backends).
/// </summary>
/// <remarks>
/// <para>
/// <b>What this can and cannot do.</b> Linux has no system-wide proxy. GSettings is a
/// <i>notification</i> mechanism: applications that honour it (GNOME/GTK, some Electron apps,
/// Firefox with the right setting) pick up the change, while anything reading its own
/// configuration — a JVM, a Go binary, a terminal tool — ignores it entirely. Setting it is
/// therefore necessary for "system proxy" mode to mean anything, and nowhere near sufficient for
/// it to be a security boundary. That is exactly why TUN mode exists, and why this executor is
/// never treated as leak protection.
/// </para>
/// <para>
/// Every value is passed to <c>gsettings</c> as a separate argv element. The bypass list is the
/// one place a value must be rendered as a GVariant string, and it is built with explicit quoting
/// rather than through a shell.
/// </para>
/// </remarks>
public sealed class LinuxSystemProxy : ISystemProxy
{
    private const string ProxySchema = "org.gnome.system.proxy";
    private const string HttpSchema = "org.gnome.system.proxy.http";
    private const string HttpsSchema = "org.gnome.system.proxy.https";
    private const string SocksSchema = "org.gnome.system.proxy.socks";

    private readonly ICommandRunner _runner;

    public LinuxSystemProxy(ICommandRunner? runner = null) => _runner = runner ?? new ProcessCommandRunner();

    /// <summary>
    /// True when the tool that applies the setting exists.
    /// </summary>
    /// <remarks>
    /// Deliberately a cheap check. The authoritative test — whether the GSettings schema is
    /// actually installed — requires running a command, and a property getter must not spawn a
    /// process. A machine with <c>gsettings</c> but no GNOME schema fails in
    /// <see cref="ApplyAsync"/> with a clear message instead.
    /// </remarks>
    public bool IsSupported => _runner.Exists("gsettings");

    public async Task<Result<SystemProxySnapshot>> CaptureAsync(CancellationToken cancellationToken)
    {
        var mode = await GetAsync(ProxySchema, "mode", cancellationToken).ConfigureAwait(false);
        if (mode is null)
        {
            return Result<SystemProxySnapshot>.Fail(NoSchema());
        }

        return Result<SystemProxySnapshot>.Ok(new SystemProxySnapshot
        {
            Mode = mode,
            Enabled = !string.Equals(mode, "none", StringComparison.OrdinalIgnoreCase),
            PacUrl = await GetAsync(ProxySchema, "autoconfig-url", cancellationToken).ConfigureAwait(false),
            HttpProxy = await DescribeAsync(HttpSchema, cancellationToken).ConfigureAwait(false),
            HttpsProxy = await DescribeAsync(HttpsSchema, cancellationToken).ConfigureAwait(false),
            SocksProxy = await DescribeAsync(SocksSchema, cancellationToken).ConfigureAwait(false),
            BypassList = await GetAsync(ProxySchema, "ignore-hosts", cancellationToken).ConfigureAwait(false),
        });
    }

    public async Task<Result> ApplyAsync(SystemProxyPlan plan, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);

        var validation = plan.Validate();
        if (validation.IsFailure)
        {
            return validation;
        }

        // Probe the schema before writing anything: a partial application that sets mode but fails
        // on the host would leave the desktop pointing at a proxy that is not there.
        var probe = await GetAsync(ProxySchema, "mode", cancellationToken).ConfigureAwait(false);
        if (probe is null)
        {
            return Result.Fail(NoSchema());
        }

        var writes = new List<(string Schema, string Key, string Value)>();

        // Ordering is deliberate: everything the proxy needs is written first, and the mode switch
        // that activates it is written last. Switching mode first would point the desktop at a
        // proxy whose host, port and bypass list are not yet in place.
        if (plan.UsePac && !string.IsNullOrWhiteSpace(plan.PacUrl))
        {
            writes.Add((ProxySchema, "autoconfig-url", plan.PacUrl!));
        }
        else
        {
            writes.Add((ProxySchema, "autoconfig-url", string.Empty));

            if (plan.EnableHttp)
            {
                writes.Add((HttpSchema, "host", "127.0.0.1"));
                writes.Add((HttpSchema, "port",
                    plan.HttpPort.ToString(CultureInfo.InvariantCulture)));
            }

            if (plan.EnableSocks)
            {
                // SOCKS is used for https as well: it is the more capable of the two and avoids
                // requiring a separate HTTPS listener.
                writes.Add((SocksSchema, "host", "127.0.0.1"));
                writes.Add((SocksSchema, "port",
                    plan.SocksPort.ToString(CultureInfo.InvariantCulture)));
            }
        }

        writes.Add((ProxySchema, "ignore-hosts", BuildBypassVariants(plan)));

        // Activation.
        writes.Add((ProxySchema, "mode", plan.UsePac && !string.IsNullOrWhiteSpace(plan.PacUrl) ? "auto" : "manual"));

        foreach (var (schema, key, value) in writes)
        {
            var written = await SetAsync(schema, key, value, cancellationToken).ConfigureAwait(false);
            if (!written.IsSuccess)
            {
                return written;
            }
        }

        return Result.Ok();
    }

    public async Task<Result> RestoreAsync(SystemProxySnapshot snapshot, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(snapshot);

        var mode = string.IsNullOrWhiteSpace(snapshot.Mode)
            ? (snapshot.Enabled ? "manual" : "none")
            : snapshot.Mode!;

        var writes = new List<(string Schema, string Key, string Value)>
        {
            (ProxySchema, "mode", mode),
            (ProxySchema, "autoconfig-url", snapshot.PacUrl ?? string.Empty),
        };

        foreach (var (schema, value) in new[]
                 {
                     (HttpSchema, snapshot.HttpProxy),
                     (HttpsSchema, snapshot.HttpsProxy),
                     (SocksSchema, snapshot.SocksProxy),
                 })
        {
            var (host, port) = SplitHostPort(value);
            writes.Add((schema, "host", host));
            writes.Add((schema, "port", port));
        }

        if (!string.IsNullOrWhiteSpace(snapshot.BypassList))
        {
            writes.Add((ProxySchema, "ignore-hosts", snapshot.BypassList!));
        }

        foreach (var (schema, key, value) in writes)
        {
            var written = await SetAsync(schema, key, value, cancellationToken).ConfigureAwait(false);
            if (!written.IsSuccess)
            {
                return written;
            }
        }

        return Result.Ok();
    }

    public async Task<Result> ResetAsync(CancellationToken cancellationToken)
    {
        // Only the mode is changed. The previously configured host and port are left untouched so
        // that a user who re-enables manual proxy mode finds their own values again rather than
        // whatever MyVpn happened to write.
        var written = await SetAsync(ProxySchema, "mode", "none", cancellationToken).ConfigureAwait(false);
        if (written.IsFailure)
        {
            return written;
        }

        var autoconfig = await SetAsync(ProxySchema, "autoconfig-url", string.Empty, cancellationToken)
            .ConfigureAwait(false);

        return autoconfig;
    }

    public async Task<SystemProxyState> InspectAsync(CancellationToken cancellationToken)
    {
        var mode = await GetAsync(ProxySchema, "mode", cancellationToken).ConfigureAwait(false);

        if (mode is null)
        {
            return new SystemProxyState { IsConfigured = false };
        }

        var http = await DescribeAsync(HttpSchema, cancellationToken).ConfigureAwait(false);
        var socks = await DescribeAsync(SocksSchema, cancellationToken).ConfigureAwait(false);
        var pac = await GetAsync(ProxySchema, "autoconfig-url", cancellationToken).ConfigureAwait(false);

        var active = !string.IsNullOrWhiteSpace(http) ? http : socks;

        // "Points at MyVpn" is judged by the loopback host, because the executor has no way to know
        // which local port MyVpn chose. A loopback proxy that is not ours would be a false
        // positive, which is why the plan carries its own ports and the kill switch does not rely
        // on this value.
        var pointsAtUs = active is not null
                         && (active.StartsWith("127.0.0.1", StringComparison.Ordinal)
                             || active.StartsWith("localhost", StringComparison.Ordinal));

        return new SystemProxyState
        {
            IsConfigured = !string.Equals(mode, "none", StringComparison.OrdinalIgnoreCase),
            ActiveProxy = active,
            PacUrl = string.IsNullOrWhiteSpace(pac) ? null : pac,
            PointsAtMyVpn = pointsAtUs,
        };
    }

    // ------------------------------------------------------------------ gsettings

    private async Task<string?> GetAsync(string schema, string key, CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync("gsettings", new[] { "get", schema, key }, cancellationToken)
            .ConfigureAwait(false);

        if (!result.Succeeded)
        {
            return null;
        }

        return Unquote(result.StandardOutput.Trim());
    }

    private async Task<Result> SetAsync(string schema, string key, string value, CancellationToken cancellationToken)
    {
        // The schema-qualified key is passed as a single argv element, so no shell is involved and
        // no value can become a command.
        var result = await _runner
            .RunAsync("gsettings", new[] { "set", schema, key, value }, cancellationToken)
            .ConfigureAwait(false);

        if (result.Succeeded)
        {
            return Result.Ok();
        }

        return Result.Fail(new MyVpnError(
            ErrorCodes.SystemProxySetFailed,
            "error.proxy.set_failed",
            ErrorSeverity.Error,
            $"gsettings set {schema} {key} failed: {result.Combined}"));
    }

    private async Task<string?> DescribeAsync(string schema, CancellationToken cancellationToken)
    {
        var host = await GetAsync(schema, "host", cancellationToken).ConfigureAwait(false);
        var port = await GetAsync(schema, "port", cancellationToken).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(host))
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(port) || port == "0" ? host : $"{host}:{port}";
    }

    /// <summary>Strips the single quotes GVariant puts around string values.</summary>
    private static string Unquote(string value)
    {
        if (value.Length >= 2 && value[0] == '\'' && value[^1] == '\'')
        {
            return value[1..^1];
        }

        return value;
    }

    private static (string Host, string Port) SplitHostPort(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return (string.Empty, "0");
        }

        var colon = value.LastIndexOf(':');
        return colon <= 0
            ? (value, "0")
            : (value[..colon], value[(colon + 1)..]);
    }

    /// <summary>
    /// Renders the bypass list as a GVariant string array.
    /// </summary>
    /// <remarks>
    /// Loopback is always included: proxying a request to the local inbound back through itself
    /// is a loop, and it breaks the verification request the connect flow makes.
    /// </remarks>
    private static string BuildBypassVariants(SystemProxyPlan plan)
    {
        var entries = new List<string> { "localhost", "127.0.0.0/8", "::1" };

        entries.AddRange(plan.BypassDomains.Where(d => !string.IsNullOrWhiteSpace(d)));
        entries.AddRange(plan.BypassNetworks.Select(n => n.ToString()));

        var distinct = entries.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        var builder = new StringBuilder("[");
        for (var i = 0; i < distinct.Length; i++)
        {
            if (i > 0)
            {
                builder.Append(", ");
            }

            // GVariant single-quoted strings; escape an embedded quote so the array stays valid.
            builder.Append('\'').Append(distinct[i].Replace("'", "\\'", StringComparison.Ordinal)).Append('\'');
        }

        return builder.Append(']').ToString();
    }

    private static MyVpnError NoSchema() =>
        new MyVpnError(
            ErrorCodes.SystemProxySetFailed,
            "error.proxy.set_failed",
            ErrorSeverity.Error,
            $"The '{ProxySchema}' GSettings schema is not available. System-proxy mode needs a "
            + "GSettings-capable desktop; TUN mode does not.",
            "diagnostics.run");
}
