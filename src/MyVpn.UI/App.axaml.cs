using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using MyVpn.Core.Domain;
using MyVpn.UI.Localization;
using MyVpn.UI.ViewModels;
using MyVpn.UI.Views;

namespace MyVpn.UI;

// Fully qualified: the sibling namespace `MyVpn.Application` would otherwise shadow
// `Avalonia.Application` when the bare identifier is resolved inside `MyVpn.UI`.
public partial class App : Avalonia.Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            // Composition root. The UI constructs only the localization service and the
            // shared state machine here; everything privileged is reached through the
            // service facade once the application layer is wired, never directly.
            var localization = new LocalizationService();
            var stateMachine = new VpnStateMachine();

            desktop.MainWindow = new MainWindow
            {
                DataContext = new MainWindowViewModel(stateMachine, localization),
            };
        }

        base.OnFrameworkInitializationCompleted();
    }
}
