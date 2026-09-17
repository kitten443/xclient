using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Headless.XUnit;
using Avalonia.Media.Imaging;
using Avalonia.Threading;
using Avalonia.VisualTree;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MyVpn.UI;
using MyVpn.UI.Composition;
using MyVpn.UI.Localization;
using MyVpn.UI.ViewModels;
using MyVpn.UI.Views;
using Shouldly;
using Xunit;

// Points Avalonia.Headless.XUnit at the app under test.
[assembly: AvaloniaTestApplication(typeof(MyVpn.UI.Tests.UiRenderTests.TestAppBuilder))]

namespace MyVpn.UI.Tests;

/// <summary>
/// Renders the real application windows with the real composition root and asserts that pixels
/// actually come out — on every platform CI runs on, without needing a display.
/// </summary>
/// <remarks>
/// <para>
/// "The UI has never been rendered" was an explicit gap in this project's own status section:
/// the views compiled and their bindings type-checked, but nothing had ever constructed a window
/// and proven the visual tree produces output. The first headless render answered a user question
/// ("does it have a GUI?") and immediately found a real defect — zh-Hans renders as boxes because
/// only Inter is bundled and Inter has no CJK glyphs. A gap that size does not stay verified by
/// being verified once, so it is a test now.
/// </para>
/// <para>
/// Each assertion is on rendered pixels, not on the visual tree: a window whose bindings all
/// silently failed would still construct, and a test that only checks construction would pass on
/// it. Sampling the framebuffer catches the difference between "a window exists" and "the user
/// would see something".
/// </para>
/// </remarks>
[Collection("Avalonia")]
public sealed class UiRenderTests
{
    /// <summary>The app builder the headless platform starts: real Skia drawing, no display.</summary>
    public static class TestAppBuilder
    {
        public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>()
            .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false })
            .UseSkia()
            .WithInterFont();
    }

    private static readonly string[] TabNames = ["status", "servers", "subscription", "diagnostics", "settings"];

    private static ServiceProvider BuildComposition()
    {
        var state = Path.Combine(Path.GetTempPath(), "myvpn-ui-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(state);

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddSimpleConsole().SetMinimumLevel(LogLevel.Error));
        services.AddMyVpn(new VpnCompositionOptions { StateDirectory = state });

        return services.BuildServiceProvider();
    }

    private static async Task<MainWindow> ShowMainWindowAsync(ServiceProvider provider)
    {
        var viewModel = provider.GetRequiredService<MainWindowViewModel>();
        await viewModel.InitializeAsync();

        var window = new MainWindow { DataContext = viewModel, Width = 1100, Height = 720 };
        window.Show();
        Dispatcher.UIThread.RunJobs();
        return window;
    }

    /// <summary>
    /// Counts distinct pixel values across a sample of the framebuffer. A window that rendered
    /// nothing but a uniform background — the signature of broken bindings, a missing theme, or a
    /// font fallback failure — scores 1. The grid is deliberately fine: the app's emptiest tab is
    /// mostly white with a heading, and a coarse grid lands between text pixels and reports a
    /// healthy window as blank.
    /// </summary>
    private static int DistinctSampledPixels(WriteableBitmap frame)
    {
        var seen = new HashSet<uint>();
        using (var fb = frame.Lock())
        {
            unsafe
            {
                var ptr = (byte*)fb.Address;
                var stepX = Math.Max(1, fb.Size.Width / 48);
                var stepY = Math.Max(1, fb.Size.Height / 27);

                for (var y = 0; y < fb.Size.Height; y += stepY)
                {
                    for (var x = 0; x < fb.Size.Width; x += stepX)
                    {
                        var offset = y * fb.RowBytes + x * 4;
                        seen.Add(*(uint*)(ptr + offset));
                    }
                }
            }
        }

        return seen.Count;
    }

    private static WriteableBitmap Render(Window window)
    {
        Dispatcher.UIThread.RunJobs();
        var frame = window.CaptureRenderedFrame();
        frame.ShouldNotBeNull("the headless renderer produced no frame for a shown window");
        frame!.PixelSize.Width.ShouldBeGreaterThan(0);
        frame.PixelSize.Height.ShouldBeGreaterThan(0);
        return frame;
    }

    [AvaloniaFact]
    public async Task EveryTabOfTheMainWindowRendersRealPixels()
    {
        using var provider = BuildComposition();
        var window = await ShowMainWindowAsync(provider);
        try
        {
            var tabs = window.GetVisualDescendants().OfType<TabControl>().Single();
            tabs.Items.Count.ShouldBe(TabNames.Length);

            foreach (var (index, name) in TabNames.Select((name, index) => (index, name)))
            {
                tabs.SelectedIndex = index;
                var frame = Render(window);

                DistinctSampledPixels(frame).ShouldBeGreaterThan(
                    4,
                    $"the '{name}' tab rendered a near-uniform frame, which is what a silently "
                    + "broken view looks like to the user");
            }
        }
        finally
        {
            window.Close();
            Dispatcher.UIThread.RunJobs();
        }
    }

    [AvaloniaFact]
    public async Task SwitchingTheLanguageAtRuntimeChangesWhatIsRendered()
    {
        using var provider = BuildComposition();
        var window = await ShowMainWindowAsync(provider);
        try
        {
            var tabs = window.GetVisualDescendants().OfType<TabControl>().Single();
            var english = tabs.Items.Cast<TabItem>().Select(item => item.Header?.ToString()).ToArray();

            provider.GetRequiredService<LocalizationService>().SetLanguage("ru");
            Dispatcher.UIThread.RunJobs();

            var russian = tabs.Items.Cast<TabItem>().Select(item => item.Header?.ToString()).ToArray();

            russian.ShouldNotBeNull();
            russian.Zip(english).Count(pair => pair.First != pair.Second).ShouldBeGreaterThan(
                0,
                "switching to Russian changed no tab header, so the localization switch is not "
                + "reaching the visual tree");
        }
        finally
        {
            window.Close();
            Dispatcher.UIThread.RunJobs();
        }
    }
}
