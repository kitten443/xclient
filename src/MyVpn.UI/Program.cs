using Avalonia;

namespace MyVpn.UI;

internal static class Program
{
    // Avalonia must run on a single-threaded apartment on Windows.
    [STAThread]
    public static void Main(string[] args) =>
        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);

    /// <summary>Also used by the Avalonia designer, so it must stay public and side-effect free.</summary>
    public static AppBuilder BuildAvaloniaApp() =>
        AppBuilder.Configure<App>()
            .UsePlatformDetect()
            .WithInterFont()
            .LogToTrace();
}
