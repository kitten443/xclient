namespace MyVpn.Rootless.Harness;

/// <summary>
/// Everything a rootless run observed, as raw data.
/// </summary>
/// <remarks>
/// <para>
/// This type is the contract between the harness (which lives inside the throwaway namespace and
/// has the privileges to look at the kernel state) and the xUnit test (which runs on the host and
/// decides whether what was observed is acceptable). The harness deliberately makes almost no
/// judgements: it records what <c>ip</c>, the resolver file and <c>nft</c> actually said, so the
/// assertions live in one place and can quote the real values.
/// </para>
/// <para>
/// Nothing here is inferred. A field is only populated from a command that ran or a file that was
/// read; a probe that failed leaves an empty string rather than a plausible-looking default.
/// </para>
/// </remarks>
public sealed class RootlessReport
{
    /// <summary>True when the scenario ran to the end and teardown completed.</summary>
    public bool Completed { get; set; }

    /// <summary>Harness-level failure (setup, teardown, or the composition throwing).</summary>
    public string? Failure { get; set; }

    /// <summary>Ordered human-readable narration, for the test output.</summary>
    public List<string> Trace { get; set; } = new();

    /// <summary>Kill-switch mode this run used: <c>off</c> or <c>on-demand</c>.</summary>
    public string KillSwitchMode { get; set; } = "off";

    /// <summary>Observations made inside the client namespace.</summary>
    public ClientObservations Client { get; set; } = new();

    /// <summary>Observations reported by the far side of the tunnel.</summary>
    public ServerObservations Server { get; set; } = new();
}

/// <summary>What the client namespace looked like before, during and after the tunnel.</summary>
public sealed class ClientObservations
{
    // ---- namespace setup, before anything MyVpn ran --------------------------

    /// <summary>Interface names present right after the uplink was configured.</summary>
    public List<string> InterfacesBeforeConnect { get; set; } = new();

    /// <summary><c>ip -4 route show default</c> before the connect.</summary>
    public string UplinkDefaultRoute { get; set; } = string.Empty;

    /// <summary><c>ip -4 route get &lt;target&gt;</c> before the connect.</summary>
    public string RouteToTargetBeforeConnect { get; set; } = string.Empty;

    /// <summary>The throwaway <c>resolv.conf</c> written before the connect.</summary>
    public string ResolvConfBeforeConnect { get; set; } = string.Empty;

    /// <summary>HTTP status of a direct request to the target before the connect (-1 = no reply).</summary>
    public int DirectRequestStatus { get; set; } = -1;

    /// <summary>Body of that request; the target stamps the source address it observed.</summary>
    public string DirectRequestBody { get; set; } = string.Empty;

    // ---- the connect ---------------------------------------------------------

    public bool ConnectSucceeded { get; set; }

    /// <summary>Error code and detail when the connect failed.</summary>
    public string? ConnectError { get; set; }

    /// <summary>Resolved server endpoints the session pinned, as <c>address:port</c>.</summary>
    public List<string> ResolvedEndpoints { get; set; } = new();

    /// <summary>Warnings the session attached to the connected snapshot.</summary>
    public List<string> ConnectWarnings { get; set; } = new();

    /// <summary>PID of the core process the supervisor started.</summary>
    public int CoreProcessId { get; set; }

    /// <summary>Nftables kill-switch table contents while connected (empty when absent).</summary>
    public string NftTableWhileConnected { get; set; } = string.Empty;

    // ---- while connected -----------------------------------------------------

    /// <summary>The tunnel interface name MyVpn used.</summary>
    public string TunInterfaceName { get; set; } = string.Empty;

    /// <summary><c>true</c> when the tunnel interface existed while connected.</summary>
    public bool TunExistsWhileConnected { get; set; }

    /// <summary>Addresses the production TUN observer read back, e.g. <c>172.19.0.1/30</c>.</summary>
    public List<string> TunAddresses { get; set; } = new();

    /// <summary><c>ip -4 route show default</c> while connected.</summary>
    public string DefaultRouteWhileConnected { get; set; } = string.Empty;

    /// <summary><c>ip -4 route get &lt;server&gt;</c> while connected — the loop-prevention route.</summary>
    public string RouteToServerWhileConnected { get; set; } = string.Empty;

    /// <summary><c>ip -4 route get &lt;target&gt;</c> while connected — must be the tunnel.</summary>
    public string RouteToTargetWhileConnected { get; set; } = string.Empty;

    /// <summary>The throwaway <c>resolv.conf</c> while connected.</summary>
    public string ResolvConfWhileConnected { get; set; } = string.Empty;

    /// <summary>Backend the DNS executor selected (never trusted blindly; recorded for honesty).</summary>
    public string DnsBackendName { get; set; } = string.Empty;

    /// <summary>Resolvers the DNS executor recorded as the previous state.</summary>
    public List<string> DnsRecordedPreviousServers { get; set; } = new();

    /// <summary>HTTP status of a request sent to the target while connected (-1 = no reply).</summary>
    public int TunnelRequestStatus { get; set; } = -1;

    /// <summary>Body of that request; the target stamps the source address it observed.</summary>
    public string TunnelRequestBody { get; set; } = string.Empty;

    /// <summary>Time until the first response byte of the tunnelled request, in milliseconds.</summary>
    public double TunnelRequestFirstByteMilliseconds { get; set; }

    /// <summary>
    /// Total time of the tunnelled request, in milliseconds.
    /// </summary>
    /// <remarks>
    /// Measured to the last body byte the headers promised, not to the connection close, so this is
    /// request latency rather than a mixture of latency and the peer's teardown.
    /// </remarks>
    public double TunnelRequestMilliseconds { get; set; }

    /// <summary>Time until the first response byte of the direct (pre-connect) request.</summary>
    public double DirectRequestFirstByteMilliseconds { get; set; }

    /// <summary>Tail of the client core's own log, which is what explains what a request did.</summary>
    public List<string> CoreLogTail { get; set; } = new();

    // ---- after the disconnect ------------------------------------------------

    public bool DisconnectSucceeded { get; set; }

    public string? DisconnectError { get; set; }

    /// <summary><c>true</c> when the tunnel interface was still present after the disconnect.</summary>
    public bool TunExistsAfterDisconnect { get; set; }

    /// <summary><c>ip -4 route show default</c> after the disconnect.</summary>
    public string DefaultRouteAfterDisconnect { get; set; } = string.Empty;

    /// <summary><c>ip -4 route get &lt;target&gt;</c> after the disconnect.</summary>
    public string RouteToTargetAfterDisconnect { get; set; } = string.Empty;

    /// <summary><c>ip -4 route get &lt;server&gt;</c> after the disconnect.</summary>
    public string RouteToServerAfterDisconnect { get; set; } = string.Empty;

    /// <summary>The throwaway <c>resolv.conf</c> after the disconnect.</summary>
    public string ResolvConfAfterDisconnect { get; set; } = string.Empty;

    /// <summary>Nftables kill-switch table contents after the disconnect (empty when absent).</summary>
    public string NftTableAfterDisconnect { get; set; } = string.Empty;

    /// <summary>Interface names left in the namespace after the disconnect.</summary>
    public List<string> InterfacesAfterDisconnect { get; set; } = new();

    /// <summary>
    /// Processes still alive in the client namespace whose executable is the core, counted by
    /// comparing <c>/proc/&lt;pid&gt;/ns/net</c> with our own.
    /// </summary>
    public int CoreProcessesInNamespaceAfterDisconnect { get; set; } = -1;

    /// <summary>Whether the dbus socket was hidden, which is what forces the file DNS backend.</summary>
    public bool DbusSocketHidden { get; set; }

    /// <summary>
    /// Set when the host's systemd-resolved is still reachable from inside the namespace.
    /// </summary>
    /// <remarks>
    /// A condition for skipping, not a product failure: the DNS executor would resolve this
    /// namespace's interface index against the <i>host's</i> resolver over the shared bus, and this
    /// harness will not risk modifying the host's DNS to prove a point.
    /// </remarks>
    public bool DnsIsolationFailed { get; set; }
}

/// <summary>What the far side of the tunnel saw.</summary>
public sealed class ServerObservations
{
    /// <summary>Interface addresses configured on the far side.</summary>
    public List<string> Addresses { get; set; } = new();

    /// <summary>Every request the target served, as <c>source -&gt; request line</c>.</summary>
    public List<string> ServedRequests { get; set; } = new();

    /// <summary>Whether the VLESS inbound was accepting connections before the client connected.</summary>
    public bool VlessPortReachable { get; set; }

    /// <summary>Tail of the server core's log, for diagnosis when something does not line up.</summary>
    public string CoreLogTail { get; set; } = string.Empty;
}
