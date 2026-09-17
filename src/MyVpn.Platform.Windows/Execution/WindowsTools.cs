using System.Globalization;
using System.Runtime.InteropServices;
using MyVpn.Core.Results;

namespace MyVpn.Platform.Windows.Execution;

/// <summary>
/// Capability, privilege and tool-path helpers shared by every Windows executor.
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing in this file may execute on a non-Windows host.</b> Every member that could
/// touch the operating system is either a pure string/argument helper or is fronted by a
/// probe that answers without calling into native code when
/// <see cref="IsWindows"/> is false. The whole platform layer is compiled as plain
/// <c>net8.0</c> and its unit tests run on Linux, so an unguarded <c>DllImport</c> call
/// would be a test-run crash rather than a compile error.
/// </para>
/// <para>
/// <b>Why the tool paths are resolved here.</b> A privileged helper started by the Service
/// Control Manager runs with a working directory of <c>C:\Windows\System32</c> and a
/// minimal <c>PATH</c>. <c>route.exe</c> and <c>netsh.exe</c> are in-box tools of the
/// system directory, so the absolute path is preferred and the bare name is only a
/// fallback; the same reasoning the Linux layer applies to <c>/usr/sbin/ip</c>.
/// </para>
/// <para>
/// <b>What is runtime-unverified.</b> This file contains P/Invoke declarations for
/// <c>iphlpapi.dll</c> and <c>advapi32.dll</c> that compile and marshal on any host but
/// can only be <i>executed</i> on Windows. They are therefore written to fail safe: every
/// probe returns "unknown"/<c>false</c> rather than throwing, and no caller treats a failed
/// probe as success.
/// </para>
/// </remarks>
public static class WindowsPlatform
{
    /// <summary>The in-box IPv4 route tool. IPv4 only; IPv6 uses <c>netsh interface ipv6</c>.</summary>
    public const string RouteTool = "route.exe";

    /// <summary>The in-box configuration tool, used for DNS and IPv6 routes.</summary>
    public const string NetshTool = "netsh.exe";

    /// <summary>
    /// True when this process is running on Windows at all.
    /// </summary>
    /// <remarks>
    /// This is the outermost guard for the entire platform layer, and it is deliberately a
    /// property rather than a cached field: <see cref="OperatingSystem.IsWindows"/> is
    /// recognised by the platform-compatibility analyser, which is what keeps the
    /// Windows-only registry and P/Invoke call sites warning-free in a cross-platform
    /// build without a <c>net8.0-windows</c> target framework.
    /// </remarks>
    public static bool IsWindows => OperatingSystem.IsWindows();

    /// <summary>
    /// Resolves an in-box tool to its absolute system path when that path exists.
    /// </summary>
    /// <remarks>
    /// Falls back to the bare file name so a command runner that searches <c>PATH</c> still
    /// finds the tool on a host where the system directory cannot be queried. On a
    /// non-Windows host the bare name is returned without touching the file system, which
    /// matters only for diagnostics: no executor calls this unless <see cref="IsWindows"/>.
    /// </remarks>
    public static string SystemTool(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        if (IsWindows)
        {
            var directory = Environment.GetFolderPath(Environment.SpecialFolder.System);

            if (!string.IsNullOrWhiteSpace(directory))
            {
                var candidate = Path.Combine(directory, fileName);
                if (File.Exists(candidate))
                {
                    return candidate;
                }
            }
        }

        return fileName;
    }

    /// <summary>
    /// True when the current process token is elevated (or is the SYSTEM account).
    /// </summary>
    /// <remarks>
    /// <para>
    /// The WFP policy engine, the routing table and per-interface DNS all require
    /// administrative rights, so an unelevated process must say so <i>before</i> the connect
    /// flow stages a configuration. This is the Windows counterpart of the Linux layer's
    /// <c>geteuid() == 0</c> probe.
    /// </para>
    /// <para>
    /// It is implemented with <c>GetTokenInformation(TokenElevation)</c> rather than
    /// <c>WindowsIdentity</c> because the latter lives in an assembly that is not part of
    /// the base shared framework for a plain <c>net8.0</c> target, and the project does not
    /// take extra package references. Any failure — a missing export, a refused token
    /// query — is reported as "not elevated": the safe direction, because the caller then
    /// refuses to arm rather than claiming a capability it may not have.
    /// </para>
    /// </remarks>
    public static bool IsProcessElevated()
    {
        if (!IsWindows)
        {
            // Unreachable through every executor (each checks IsWindows first) and returned
            // rather than thrown so a mistaken call can never break a Linux test run.
            return false;
        }

        var token = IntPtr.Zero;
        var buffer = IntPtr.Zero;

        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token))
            {
                return false;
            }

            buffer = Marshal.AllocHGlobal(sizeof(int));

            if (!GetTokenInformation(token, TokenElevation, buffer, sizeof(int), out _))
            {
                return false;
            }

            return Marshal.ReadInt32(buffer) != 0;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            return false;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }

            if (token != IntPtr.Zero)
            {
                CloseHandle(token);
            }
        }
    }

    /// <summary>
    /// The refusal returned by every executor on a host that is not Windows.
    /// </summary>
    /// <remarks>
    /// <see cref="ErrorCodes.PlatformUnsupported"/> with the <c>error.platform.unsupported</c>
    /// localization key, never a raw English sentence in the key position. The technical
    /// detail names the executor so a diagnostics bundle shows which call was refused.
    /// </remarks>
    public static MyVpnError Unsupported(string executor) =>
        new MyVpnError(
            ErrorCodes.PlatformUnsupported,
            "error.platform.unsupported",
            ErrorSeverity.Error,
            $"{executor} requires Windows: the host reports "
            + $"{RuntimeInformation.OSDescription} and none of the Win32/WFP calls this "
            + "executor makes may run here. Nothing was changed.",
            "diagnostics.run");

    /// <summary>The refusal returned when the process is not elevated.</summary>
    public static MyVpnError NotElevated(string messageKey, string detail, string? remediationKey = null) =>
        new MyVpnError(
            ErrorCodes.PrivilegeDenied,
            messageKey,
            ErrorSeverity.Error,
            detail,
            remediationKey);

    /// <summary>An in-box tool that this build expects but the host does not have.</summary>
    public static MyVpnError ToolMissing(string tool, string remediationKey) =>
        new MyVpnError(
            ErrorCodes.PlatformToolMissing,
            "error.platform.tool_missing",
            ErrorSeverity.Error,
            $"The '{tool}' command is not available, so this step cannot be performed.",
            remediationKey)
        .WithArg("tool", tool);

    /// <summary>Flattens platform output to one bounded line for logs and diagnostics.</summary>
    public static string Trim(string? value, int maxLength = 300)
    {
        var text = (value ?? string.Empty).Replace('\n', ' ').Replace('\r', ' ').Trim();
        return text.Length <= maxLength ? text : text[..maxLength] + "…";
    }

    private const uint TokenQuery = 0x0008;
    private const int TokenElevation = 20;

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = false)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle,
        int tokenInformationClass,
        IntPtr tokenInformation,
        int tokenInformationLength,
        out int returnLength);

    [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = false)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>
/// One network adapter as <c>GetAdaptersAddresses</c> reports it.
/// </summary>
/// <remarks>
/// <para>
/// Only the fields MyVpn reasons about are carried. The Windows equivalent of the Linux
/// layer's <c>ip link</c> output is this API rather than parsed text, because every
/// <c>netsh</c>/<c>ipconfig</c> listing is localized and a parser keyed on English labels
/// silently returns nothing on a non-English Windows installation.
/// </para>
/// <para>
/// <b>The index is not a stable identifier.</b> Windows reassigns interface indexes across
/// restarts and adapter re-creation, and Wintun adapters are created and destroyed with the
/// tunnel, so anything that pins an index must re-resolve it from the adapter name (or,
/// better, use the LUID within a session) instead of persisting it. That finding is why
/// this type carries the name, the index and the LUID together.
/// </para>
/// </remarks>
public sealed record WindowsAdapterInfo
{
    /// <summary>User-visible name, e.g. <c>myvpn0</c> or <c>Ethernet</c>.</summary>
    public required string FriendlyName { get; init; }

    /// <summary>Driver-supplied description, e.g. <c>Wintun Userspace Tunnel</c>.</summary>
    public string? Description { get; init; }

    /// <summary>The adapter's GUID string (<c>{...}</c>), the stable identity across a session.</summary>
    public string? AdapterName { get; init; }

    /// <summary>IPv4 interface index as currently assigned. Not stable across restarts.</summary>
    public required uint IfIndex { get; init; }

    public uint Ipv6IfIndex { get; init; }

    /// <summary>The interface LUID, which the WFP TUN permit must match.</summary>
    public required ulong Luid { get; init; }

    public uint Mtu { get; init; }

    /// <summary><c>IF_OPER_STATUS</c>; 1 is <c>IfOperStatusUp</c>.</summary>
    public uint OperStatus { get; init; }

    /// <summary>Unicast addresses in <c>address/prefix</c> form, as the routing layer needs them.</summary>
    public IReadOnlyList<string> Addresses { get; init; } = Array.Empty<string>();

    public bool IsUp => OperStatus == 1;
}

/// <summary>
/// Adapter enumeration over <c>GetAdaptersAddresses</c> (<c>iphlpapi.dll</c>).
/// </summary>
/// <remarks>
/// <para>
/// Used by three executors that must agree on one view of the machine: the TUN observer
/// (does the interface exist, what addresses does it hold), the route manager (which
/// numeric index does <c>route.exe</c> need for a name) and the Kill Switch (which LUID
/// does the TUN permit match). Keeping one implementation is what stops those three from
/// disagreeing after a reconnect.
/// </para>
/// <para>
/// Every public member answers without touching native code when
/// <see cref="WindowsPlatform.IsWindows"/> is false, so the Linux test run exercises the
/// refusal path rather than the marshalling path.
/// </para>
/// </remarks>
public static class WindowsAdapters
{
    private const uint AddressFamilyUnspecified = 0;
    private const uint GetAll = 0x0010 | 0x0002 | 0x0004;

    private const uint ErrorSuccess = 0;
    private const uint ErrorBufferOverflow = 111;

    private const int InitialBufferSize = 16 * 1024;

    private const ushort AddressFamilyInet = 2;
    private const ushort AddressFamilyInet6 = 23;

    /// <summary>
    /// Enumerates the current adapters, or returns an empty list with a reason.
    /// </summary>
    /// <remarks>
    /// Never throws: a failed enumeration is reported through <paramref name="error"/> so a
    /// caller can put it in a diagnostics detail line. An empty list must be read as
    /// "unknown", not as "no adapters", whenever <paramref name="error"/> is non-null.
    /// </remarks>
    public static IReadOnlyList<WindowsAdapterInfo> Enumerate(out string? error)
    {
        error = null;

        if (!WindowsPlatform.IsWindows)
        {
            error = "GetAdaptersAddresses is only available on Windows.";
            return Array.Empty<WindowsAdapterInfo>();
        }

        var size = (uint)InitialBufferSize;
        var buffer = Marshal.AllocHGlobal((int)size);

        try
        {
            var result = GetAdaptersAddresses(AddressFamilyUnspecified, GetAll, IntPtr.Zero, buffer, ref size);

            if (result == ErrorBufferOverflow)
            {
                // Documented two-call pattern: the API reports the required size in `size`.
                // The retry is bounded by a single reallocation rather than a loop, because a
                // machine that grows its adapter list between the two calls is a race the
                // caller resolves by re-enumerating.
                Marshal.FreeHGlobal(buffer);
                buffer = Marshal.AllocHGlobal((int)size);
                result = GetAdaptersAddresses(AddressFamilyUnspecified, GetAll, IntPtr.Zero, buffer, ref size);
            }

            if (result != ErrorSuccess)
            {
                error = $"GetAdaptersAddresses failed with Win32 error {result.ToString(CultureInfo.InvariantCulture)}.";
                return Array.Empty<WindowsAdapterInfo>();
            }

            var adapters = new List<WindowsAdapterInfo>();
            var current = buffer;

            while (current != IntPtr.Zero)
            {
                var native = Marshal.PtrToStructure<NativeAdapterAddresses>(current);
                adapters.Add(Convert(native));
                current = native.Next;
            }

            return adapters;
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException)
        {
            error = $"GetAdaptersAddresses could not be resolved: {ex.Message}";
            return Array.Empty<WindowsAdapterInfo>();
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>Finds an adapter by its friendly name (case-insensitive, ordinal).</summary>
    public static WindowsAdapterInfo? FindByName(string interfaceName)
    {
        if (string.IsNullOrWhiteSpace(interfaceName))
        {
            return null;
        }

        foreach (var adapter in Enumerate(out _))
        {
            if (string.Equals(adapter.FriendlyName, interfaceName, StringComparison.OrdinalIgnoreCase))
            {
                return adapter;
            }
        }

        return null;
    }

    /// <summary>
    /// Resolves a friendly name to the interface LUID the WFP TUN permit needs.
    /// </summary>
    /// <remarks>
    /// Called at apply time, never cached beyond the operation: a Wintun adapter is created
    /// and destroyed with the tunnel, and its LUID changes when it is re-created.
    /// </remarks>
    public static bool TryGetLuid(string interfaceName, out ulong luid)
    {
        luid = 0;

        if (!WindowsPlatform.IsWindows)
        {
            return false;
        }

        var adapter = FindByName(interfaceName);
        if (adapter is null || adapter.Luid == 0)
        {
            return false;
        }

        luid = adapter.Luid;
        return true;
    }

    /// <summary>
    /// Resolves a friendly name to the numeric index <c>route.exe</c>'s <c>if</c> clause takes.
    /// </summary>
    /// <remarks>
    /// The index is deliberately re-resolved on every apply rather than remembered: Windows
    /// reassigns interface indexes across restarts and adapter re-creation, so a persisted
    /// index silently points at a different interface — or at nothing — on the next run.
    /// </remarks>
    public static bool TryGetInterfaceIndex(string interfaceName, out uint index)
    {
        index = 0;

        if (!WindowsPlatform.IsWindows)
        {
            return false;
        }

        var adapter = FindByName(interfaceName);
        if (adapter is null || adapter.IfIndex == 0)
        {
            return false;
        }

        index = adapter.IfIndex;
        return true;
    }

    private static WindowsAdapterInfo Convert(NativeAdapterAddresses native) => new()
    {
        FriendlyName = Marshal.PtrToStringUni(native.FriendlyName) ?? string.Empty,
        Description = Marshal.PtrToStringUni(native.Description),
        AdapterName = Marshal.PtrToStringAnsi(native.AdapterName),
        IfIndex = native.IfIndex,
        Ipv6IfIndex = native.Ipv6IfIndex,
        Luid = native.Luid,
        Mtu = native.Mtu,
        OperStatus = native.OperStatus,
        Addresses = ReadUnicastAddresses(native.FirstUnicastAddress),
    };

    private static IReadOnlyList<string> ReadUnicastAddresses(IntPtr first)
    {
        var addresses = new List<string>();
        var current = first;

        while (current != IntPtr.Zero)
        {
            var entry = Marshal.PtrToStructure<NativeUnicastAddress>(current);
            var text = FormatAddress(entry.Address.SocketAddress, entry.OnLinkPrefixLength);

            if (text is not null && !addresses.Contains(text, StringComparer.OrdinalIgnoreCase))
            {
                addresses.Add(text);
            }

            current = entry.Next;
        }

        return addresses;
    }

    /// <summary>
    /// Renders a <c>sockaddr</c> as <c>address/prefix</c>.
    /// </summary>
    /// <remarks>
    /// The socket address is read field by field instead of casting to <c>sockaddr_in</c>:
    /// both layouts start with the 16-bit family, IPv4 carries the address at offset 4 and
    /// IPv6 at offset 8, and reading four/sixteen bytes with <see cref="Marshal.Copy"/>
    /// avoids declaring two more structs whose alignment would have to be re-derived for
    /// each architecture.
    /// </remarks>
    private static string? FormatAddress(IntPtr socketAddress, byte prefixLength)
    {
        if (socketAddress == IntPtr.Zero)
        {
            return null;
        }

        var family = unchecked((ushort)Marshal.ReadInt16(socketAddress));

        if (family == AddressFamilyInet)
        {
            var bytes = new byte[4];
            Marshal.Copy(IntPtr.Add(socketAddress, 4), bytes, 0, bytes.Length);
            return $"{new System.Net.IPAddress(bytes)}/{prefixLength.ToString(CultureInfo.InvariantCulture)}";
        }

        if (family == AddressFamilyInet6)
        {
            var bytes = new byte[16];
            Marshal.Copy(IntPtr.Add(socketAddress, 8), bytes, 0, bytes.Length);
            return $"{new System.Net.IPAddress(bytes)}/{prefixLength.ToString(CultureInfo.InvariantCulture)}";
        }

        return null;
    }

    [DllImport("iphlpapi.dll", ExactSpelling = true, SetLastError = false)]
    private static extern uint GetAdaptersAddresses(
        uint family,
        uint flags,
        IntPtr reserved,
        IntPtr addresses,
        ref uint size);

    /// <summary>
    /// The leading portion of <c>IP_ADAPTER_ADDRESSES_LH</c>, up to and including the LUID.
    /// </summary>
    /// <remarks>
    /// Marshalled sequentially so the runtime computes the offsets from the documented field
    /// order; the struct is truncated after <c>Luid</c> because nothing beyond it is used,
    /// and truncating is safe as long as the field offsets before it are correct. The
    /// anonymous union at the head is represented by a single <see cref="ulong"/> with the
    /// index read at offset 4 by the marshaller's own layout, and <c>ZoneIndices</c> is a
    /// fixed-size array so the offsets that follow it — including <c>Luid</c> — stay right.
    /// </remarks>
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeAdapterAddresses
    {
        /// <summary>Union of <c>ULONGLONG Alignment</c> and <c>{ ULONG Length; IF_INDEX IfIndex; }</c>.</summary>
        public ulong Alignment;

        public IntPtr Next;
        public IntPtr AdapterName;
        public IntPtr FirstUnicastAddress;
        public IntPtr FirstAnycastAddress;
        public IntPtr FirstMulticastAddress;
        public IntPtr FirstDnsServerAddress;
        public IntPtr DnsSuffix;
        public IntPtr Description;
        public IntPtr FriendlyName;
        public ulong PhysicalAddress;
        public uint PhysicalAddressLength;
        public uint Flags;
        public uint Mtu;
        public uint IfType;
        public uint OperStatus;
        public uint Ipv6IfIndex;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public uint[] ZoneIndices;

        public IntPtr FirstPrefix;
        public ulong TransmitLinkSpeed;
        public ulong ReceiveLinkSpeed;
        public IntPtr FirstWinsServerAddress;
        public IntPtr FirstGatewayAddress;
        public uint Ipv4Metric;
        public uint Ipv6Metric;
        public ulong Luid;

        /// <summary>
        /// The IPv4 interface index, which is the second half of the head union
        /// (<c>{ ULONG Length; IF_INDEX IfIndex; }</c>) and therefore the high 32 bits on
        /// the little-endian architectures Windows runs on.
        /// </summary>
        public readonly uint IfIndex => unchecked((uint)(Alignment >> 32));
    }

    /// <summary>A <c>SOCKET_ADDRESS</c>: a pointer to a sockaddr plus its length.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeSocketAddress
    {
        public IntPtr SocketAddress;
        public int SocketAddressLength;
    }

    /// <summary>The leading portion of <c>IP_ADAPTER_UNICAST_ADDRESS_LH</c>.</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct NativeUnicastAddress
    {
        public ulong Alignment;
        public IntPtr Next;
        public NativeSocketAddress Address;
        public uint PrefixOrigin;
        public uint SuffixOrigin;
        public uint DadState;
        public uint ValidLifetime;
        public uint PreferredLifetime;
        public uint LeaseLifetime;
        public byte OnLinkPrefixLength;
    }
}
