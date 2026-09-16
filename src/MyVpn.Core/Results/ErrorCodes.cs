namespace MyVpn.Core.Results;

/// <summary>
/// Stable, machine-readable error codes.
/// </summary>
/// <remarks>
/// These strings are part of the diagnostics contract: they appear in exported
/// diagnostic bundles and in the IPC protocol, so they must stay stable even when
/// messages are reworded or translated. Never localize these values.
/// </remarks>
public static class ErrorCodes
{
    // ---- configuration -------------------------------------------------
    public const string ConfigInvalid = "config.invalid";
    public const string ConfigSerializeFailed = "config.serialize_failed";
    public const string ConfigWriteFailed = "config.write_failed";
    public const string ConfigRejectedByCore = "config.rejected_by_core";

    // ---- xray engine ---------------------------------------------------
    public const string XrayBinaryNotFound = "xray.binary_not_found";
    public const string XrayBinaryNotExecutable = "xray.binary_not_executable";
    public const string XrayVersionUnsupported = "xray.version_unsupported";
    public const string XrayVersionProbeFailed = "xray.version_probe_failed";
    public const string XrayStartFailed = "xray.start_failed";
    public const string XrayStoppedUnexpectedly = "xray.stopped_unexpectedly";
    public const string XrayRestartLoopDetected = "xray.restart_loop_detected";
    public const string XrayShutdownTimeout = "xray.shutdown_timeout";
    public const string XrayHealthCheckFailed = "xray.health_check_failed";

    // ---- geo data (v2rayN issue #9765 class of failure) ----------------
    public const string GeoAssetMissing = "geodata.missing";
    public const string GeoAssetUnreadable = "geodata.unreadable";
    public const string GeoAssetEmpty = "geodata.empty";
    public const string GeoAssetCorrupt = "geodata.corrupt";
    public const string GeoAssetChecksumMismatch = "geodata.checksum_mismatch";
    public const string GeoAssetDownloadFailed = "geodata.download_failed";
    public const string GeoAssetInstallFailed = "geodata.install_failed";
    public const string GeoAssetRollbackFailed = "geodata.rollback_failed";
    public const string GeoAssetDirectoryNotWritable = "geodata.directory_not_writable";
    public const string GeoAssetPathNotAbsolute = "geodata.path_not_absolute";

    // ---- subscriptions -------------------------------------------------
    public const string SubscriptionFetchFailed = "subscription.fetch_failed";
    public const string SubscriptionHttpError = "subscription.http_error";
    public const string SubscriptionPayloadEmpty = "subscription.payload_empty";
    public const string SubscriptionParseFailed = "subscription.parse_failed";
    public const string SubscriptionNoServers = "subscription.no_servers";
    public const string SubscriptionHeaderInvalid = "subscription.header_invalid";
    public const string SubscriptionUrlInvalid = "subscription.url_invalid";
    public const string SubscriptionUrlInsecure = "subscription.url_insecure";

    // ---- share links ---------------------------------------------------
    public const string ShareLinkUnsupportedScheme = "sharelink.unsupported_scheme";
    public const string ShareLinkMalformed = "sharelink.malformed";
    public const string ShareLinkMissingField = "sharelink.missing_field";
    public const string ShareLinkDecodeFailed = "sharelink.decode_failed";

    // ---- ipc / privilege ----------------------------------------------
    public const string IpcNotAvailable = "ipc.not_available";
    public const string IpcUnauthorized = "ipc.unauthorized";
    public const string IpcProtocolError = "ipc.protocol_error";
    public const string IpcTimeout = "ipc.timeout";
    public const string IpcMessageTooLarge = "ipc.message_too_large";
    public const string IpcRejectedByPolicy = "ipc.rejected_by_policy";
    public const string PrivilegeDenied = "privilege.denied";
    public const string PrivilegeNotElevated = "privilege.not_elevated";
    public const string PrivilegeHelperNotInstalled = "privilege.helper_not_installed";

    // ---- platform / network --------------------------------------------
    public const string PlatformUnsupported = "platform.unsupported";
    public const string PlatformToolMissing = "platform.tool_missing";
    public const string KillSwitchApplyFailed = "killswitch.apply_failed";
    public const string KillSwitchRemoveFailed = "killswitch.remove_failed";
    public const string KillSwitchVerificationFailed = "killswitch.verification_failed";
    public const string RouteAddFailed = "route.add_failed";
    public const string RouteRemoveFailed = "route.remove_failed";
    public const string DnsConfigureFailed = "dns.configure_failed";
    public const string DnsRestoreFailed = "dns.restore_failed";
    public const string DnsLeakDetected = "dns.leak_detected";
    public const string TunCreateFailed = "tun.create_failed";
    public const string TunMissing = "tun.missing";
    public const string SystemProxySetFailed = "proxy.set_failed";
    public const string SystemProxyRestoreFailed = "proxy.restore_failed";
    public const string ProcessRoutingUnsupported = "process_routing.unsupported";

    // ---- updates --------------------------------------------------------
    public const string UpdateDownloadFailed = "update.download_failed";
    public const string UpdateChecksumMismatch = "update.checksum_mismatch";
    public const string UpdateInstallFailed = "update.install_failed";
    public const string UpdateRollbackFailed = "update.rollback_failed";
    public const string UpdateSignatureInvalid = "update.signature_invalid";

    // ---- diagnostics / misc --------------------------------------------
    public const string DiagnosticsCheckFailed = "diagnostics.check_failed";
    public const string OperationCancelled = "operation.cancelled";
    public const string OperationTimeout = "operation.timeout";
    public const string NotFound = "common.not_found";
    public const string InvalidArgument = "common.invalid_argument";
}
