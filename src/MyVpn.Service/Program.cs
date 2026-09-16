using System.Globalization;
using System.Runtime.InteropServices;

namespace MyVpn.Service;

/// <summary>
/// Entry point of the privileged VPN helper.
/// </summary>
/// <remarks>
/// <para>
/// This process owns everything that requires elevation: the TUN interface, routes, the
/// firewall/Kill Switch, DNS and process routing. It runs as a system service (Windows
/// LocalSystem, a Linux root systemd unit, a macOS privileged launchd daemon) and exposes a
/// narrow, authenticated IPC surface to the unprivileged UI.
/// </para>
/// <para>
/// <b>Current state.</b> The service host, the domain logic it will expose (geo data
/// management, the Kill Switch plan/render pipeline) and the platform capability model are
/// implemented. The IPC transport and the platform executors are not yet wired, so this
/// entry point deliberately performs a privilege and capability pre-flight and then reports
/// what is and is not available rather than pretending to serve requests. Reporting honestly
/// is the point: a helper that silently does nothing is worse than one that says so.
/// </para>
/// </remarks>
internal static class Program
{
    private static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        var isElevated = CheckElevated();

        Console.WriteLine("MyVpn privileged helper");
        Console.WriteLine("=======================");
        Console.WriteLine(Format("version      : {0}", typeof(Program).Assembly.GetName().Version));
        Console.WriteLine(Format("platform     : {0}", RuntimeInformation.OSDescription));
        Console.WriteLine(Format("architecture : {0}", RuntimeInformation.OSArchitecture));
        Console.WriteLine(Format("elevated     : {0}", isElevated ? "yes" : "NO"));
        Console.WriteLine(Format("user         : {0}", Environment.UserName));
        Console.WriteLine();

        if (!isElevated)
        {
            // Refusing to continue is the correct behaviour: every operation this process
            // exists to perform needs elevation, so running unprivileged would mean either
            // failing later with a less clear error or, worse, silently doing nothing.
            Console.Error.WriteLine("This helper must run with administrative privileges.");
            Console.Error.WriteLine("It is installed by the MyVpn package, not started manually.");
            return 77; // EX_NOPERM
        }

        Console.WriteLine("Capability pre-flight:");
        Console.WriteLine(Format("  kill switch : {0}", DescribeKillSwitchMechanism()));
        Console.WriteLine(Format("  tun device  : {0}", File.Exists("/dev/net/tun") || OperatingSystem.IsWindows()
            ? "present" : "MISSING (/dev/net/tun)"));
        Console.WriteLine();

        Console.WriteLine("The IPC listener and platform executors are not yet wired in this build.");
        Console.WriteLine("No network state has been changed.");

        return 0;
    }

    /// <summary>
    /// Reports whether the process holds administrative rights on the current platform.
    /// </summary>
    /// <remarks>
    /// On Unix the effective user id is authoritative. On Windows the check uses the
    /// WindowsPrincipal role rather than attempting to open a privileged resource, so it does
    /// not require a side effect.
    /// </remarks>
    private static bool CheckElevated()
    {
        if (OperatingSystem.IsWindows())
        {
            try
            {
                using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            catch (Exception ex) when (ex is PlatformNotSupportedException or InvalidOperationException)
            {
                return false;
            }
        }

        return GetEffectiveUserId() == 0;
    }

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = false)]
    private static extern uint GetEffectiveUserId();

    private static string DescribeKillSwitchMechanism()
    {
        if (OperatingSystem.IsWindows())
        {
            return "Windows Filtering Platform (WFP) via fwpuclnt.dll";
        }

        if (OperatingSystem.IsMacOS())
        {
            return "PF anchors (best-effort; see ADR-0006)";
        }

        if (OperatingSystem.IsLinux())
        {
            return File.Exists("/usr/sbin/nft") || File.Exists("/usr/bin/nft")
                ? "nftables"
                : "iptables (nftables unavailable)";
        }

        return "unsupported platform";
    }

    private static string Format(string template, params object?[] arguments) =>
        string.Format(CultureInfo.InvariantCulture, template, arguments);
}
