using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using MyVpn.UI.Composition;
using MyVpn.UI.ViewModels;
using MyVpn.UI.Views;

namespace MyVpn.UI;

// Fully qualified: the sibling namespace `MyVpn.Application` would otherwise shadow
// `Avalonia.Application` when the bare identifier is resolved inside `MyVpn.UI`.
public partial class App : Avalonia.Application
{
    private ServiceProvider? _services;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // The composition root, and the only place in this project that knows a concrete
            // platform type exists. Everything below the window is built once, here, and is
            // reached through interfaces from then on — which is what keeps a privileged call
            // out of a click handler.
            var services = new ServiceCollection();
            services.AddLogging(builder => builder.AddSimpleConsole().SetMinimumLevel(LogLevel.Warning));
            services.AddMyVpn();

            _services = services.BuildServiceProvider();

            var viewModel = _services.GetRequiredService<MainWindowViewModel>();

            // Started, not awaited. Loading the profile list is local file I/O and the connect
            // path is not reachable until a profile is selected, so nothing is at risk while it
            // completes — and blocking here would deadlock the very UI thread the continuation
            // has to run on.
            Observe(viewModel.InitializeAsync());

            desktop.MainWindow = new MainWindow { DataContext = viewModel };

            // The container owns the core supervisor, the subscription HTTP client and the
            // platform executors, so it has to be disposed or the Xray process outlives the
            // window that started it.
            desktop.Exit += (_, _) =>
            {
                _services?.Dispose();
                _services = null;
            };
        }

        base.OnFrameworkInitializationCompleted();
    }

    /// <summary>
    /// Runs a startup task without awaiting it, surfacing a failure instead of losing it.
    /// </summary>
    /// <remarks>
    /// An unobserved faulted task is silently swallowed by the runtime; a startup that failed
    /// must at least reach a log, because the symptom otherwise is an empty server list and no
    /// explanation.
    /// </remarks>
    private static void Observe(Task task) => _ = task.ContinueWith(
        completed => System.Diagnostics.Trace.TraceError(
            "Startup task failed: {0}",
            completed.Exception?.GetBaseException()),
        CancellationToken.None,
        TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
        TaskScheduler.Default);
}
