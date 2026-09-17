using Avalonia.Controls;

namespace MyVpn.UI.Views;

/// <summary>
/// Connect tab. Code-behind is intentionally empty: all behaviour lives in the view model,
/// which is what keeps the view model testable and the view replaceable.
/// </summary>
public partial class ConnectionView : UserControl
{
    public ConnectionView()
    {
        InitializeComponent();
    }
}
