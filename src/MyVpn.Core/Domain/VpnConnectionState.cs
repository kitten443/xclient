namespace MyVpn.Core.Domain;

/// <summary>
/// The lifecycle of the VPN tunnel.
/// </summary>
/// <remarks>
/// <see cref="Degraded"/> and <see cref="Faulted"/> are deliberately distinct:
/// <list type="bullet">
/// <item><description>
/// <see cref="Degraded"/> means the tunnel is technically up but health checks are
/// failing (packet loss, core restarts, DNS not resolving). The user is still
/// protected, so we must NOT tear the tunnel down or drop the Kill Switch.
/// </description></item>
/// <item><description>
/// <see cref="Faulted"/> means we could not establish or maintain a correct state
/// and the Kill Switch may be the only thing keeping the user safe. In this state
/// the Kill Switch must stay engaged until either recovery succeeds or the user
/// explicitly runs "restore network" (Emergency Cleanup).
/// </description></item>
/// </list>
/// This distinction is a security property, not cosmetics: a naive
/// connected/disconnected model encourages "disconnect == tear everything down",
/// which is exactly how leak windows are created.
/// </remarks>
public enum VpnConnectionState
{
    /// <summary>No tunnel, no Kill Switch, network is untouched.</summary>
    Disconnected = 0,

    /// <summary>
    /// Validating inputs before touching the network: resolving the server,
    /// verifying geo data, generating and checking the Xray configuration.
    /// </summary>
    Preparing = 1,

    /// <summary>The core is starting and routes/firewall are being staged.</summary>
    Connecting = 2,

    /// <summary>Tunnel established and health checks pass.</summary>
    Connected = 3,

    /// <summary>Tunnel is up but health checks are failing.</summary>
    Degraded = 4,

    /// <summary>An established session is being re-established (server switch, core crash).</summary>
    Reconnecting = 5,

    /// <summary>An orderly teardown is in progress.</summary>
    Disconnecting = 6,

    /// <summary>We could not reach a correct state; the Kill Switch stays engaged.</summary>
    Faulted = 7,
}

public static class VpnConnectionStateExtensions
{
    /// <summary>True while the state machine is mid-transition.</summary>
    public static bool IsTransitional(this VpnConnectionState state) =>
        state is VpnConnectionState.Preparing
            or VpnConnectionState.Connecting
            or VpnConnectionState.Reconnecting
            or VpnConnectionState.Disconnecting;

    /// <summary>
    /// True when user traffic is expected to be flowing through the tunnel
    /// (possibly impaired).
    /// </summary>
    public static bool IsTunnelUp(this VpnConnectionState state) =>
        state is VpnConnectionState.Connected
            or VpnConnectionState.Degraded
            or VpnConnectionState.Reconnecting;

    /// <summary>
    /// True when the Kill Switch must be engaged. Note that <see cref="VpnConnectionState.Faulted"/>
    /// keeps the Kill Switch on: failing open is never acceptable.
    /// </summary>
    public static bool RequiresKillSwitch(this VpnConnectionState state) =>
        state is VpnConnectionState.Connected
            or VpnConnectionState.Degraded
            or VpnConnectionState.Reconnecting
            or VpnConnectionState.Faulted
            or VpnConnectionState.Disconnecting;
}
