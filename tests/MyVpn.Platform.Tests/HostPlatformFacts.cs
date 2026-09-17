using Xunit;

namespace MyVpn.Platform.Tests;

// The Windows and macOS executor suites are written against a host that is NOT the platform
// they describe. That is not an accident of where they were authored -- it is the only safe
// way to test these executors in a shared CI runner.
//
// Both suites drive the real executor with `isElevated: () => true` and assert that it
// REFUSES, because every OS call is behind an `OperatingSystem.IsWindows()` / `IsMacOS()`
// guard. On the matching host those guards open instead of closing, so the same tests would
// touch live kernel state on the runner: WindowsWfpKillSwitch would install real WFP filters,
// WindowsSystemProxy would rewrite the runner's WinINet proxy settings, MacPfKillSwitch would
// load PF anchors, and MacDnsConfigurator would repoint the runner's resolver. The assertions
// they make ("IsSupported is false", "the call refuses") are also simply not true there, so
// they fail for the right reason while doing damage on the way.
//
// Skipping is the honest outcome and it is deliberately visible: xunit reports these as
// skipped with a reason, so the gap shows up in every run instead of hiding. Making them pass
// on their own platform means actually running privileged WFP/PF/networksetup operations,
// which is the runtime-verification task tracked in the README, not something to smuggle into
// a unit-test job.

/// <summary>
/// The skip decision, as a pure function of the host platform.
/// </summary>
/// <remarks>
/// Separated from the attributes so it can be tested on any host. A VPN client's test suite
/// should not contain a rule whose only verification is "it looked right in review on Linux",
/// and this project's own README calls a vacuous green run a defect rather than a pass: with
/// the predicate extracted, both branches are exercised by
/// <see cref="HostPlatformGuardPolicyTests"/> on whatever machine runs the tests.
/// </remarks>
internal static class HostPlatformGuard
{
    internal const string WindowsSkipReason =
        "This suite exercises the Windows executors from a non-Windows host and asserts their "
        + "refusal path. On Windows the same calls reach real WFP, WinINet and netsh state, which "
        + "a unit-test job must not touch. Runtime verification of these executors on Windows is "
        + "tracked in the README.";

    internal const string MacSkipReason =
        "This suite exercises the macOS executors from a non-macOS host and asserts their refusal "
        + "path. On macOS the same calls load PF anchors and repoint the system resolver and proxy, "
        + "which a unit-test job must not touch. Runtime verification of these executors on macOS "
        + "is tracked in the README.";

    /// <summary>The skip reason for a Windows-executor suite, or null when it may run.</summary>
    internal static string? ForWindowsSuite(bool hostIsWindows) => hostIsWindows ? WindowsSkipReason : null;

    /// <summary>The skip reason for a macOS-executor suite, or null when it may run.</summary>
    internal static string? ForMacSuite(bool hostIsMacOS) => hostIsMacOS ? MacSkipReason : null;
}

/// <summary>
/// A fact that runs only when the host is not Windows, because the suite it belongs to
/// asserts the behaviour of the Windows executors' non-Windows refusal path.
/// </summary>
public sealed class FactOnNonWindowsAttribute : FactAttribute
{
    public FactOnNonWindowsAttribute() => Skip = HostPlatformGuard.ForWindowsSuite(OperatingSystem.IsWindows());
}

/// <summary>A <see cref="Theory"/> equivalent of <see cref="FactOnNonWindowsAttribute"/>.</summary>
public sealed class TheoryOnNonWindowsAttribute : TheoryAttribute
{
    public TheoryOnNonWindowsAttribute() => Skip = HostPlatformGuard.ForWindowsSuite(OperatingSystem.IsWindows());
}

/// <summary>
/// A fact that runs only when the host is not macOS, for the same reason as
/// <see cref="FactOnNonWindowsAttribute"/>: on macOS the PF, <c>networksetup</c> and
/// <c>route</c> guards open and the suite would change the runner's live networking.
/// </summary>
public sealed class FactOnNonMacOSAttribute : FactAttribute
{
    public FactOnNonMacOSAttribute() => Skip = HostPlatformGuard.ForMacSuite(OperatingSystem.IsMacOS());
}

/// <summary>A <see cref="Theory"/> equivalent of <see cref="FactOnNonMacOSAttribute"/>.</summary>
public sealed class TheoryOnNonMacOSAttribute : TheoryAttribute
{
    public TheoryOnNonMacOSAttribute() => Skip = HostPlatformGuard.ForMacSuite(OperatingSystem.IsMacOS());
}
