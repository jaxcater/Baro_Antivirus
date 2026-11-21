using System.Windows;

namespace BaroAntivirus.Setup;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        bool isUninstall = e.Args.Any(a => a.Equals("--uninstall", StringComparison.OrdinalIgnoreCase));
        bool isSilent = e.Args.Any(a => a.Equals("--silent", StringComparison.OrdinalIgnoreCase) || a.Equals("/S", StringComparison.OrdinalIgnoreCase));

        var win = new SetupWindow(isUninstall, isSilent);
        if (isSilent)
        {
            _ = win.RunSilentAsync();
        }
        else
        {
            win.Show();
        }
    }
}
