using System.Drawing;
using System.Drawing.Drawing2D;
using WinForms = System.Windows.Forms;

namespace BaroAntivirus.App;

public sealed class TrayService : IDisposable
{
    private readonly WinForms.NotifyIcon _notifyIcon;
    private readonly WinForms.ToolStripMenuItem _toggleRealtimeItem;
    private readonly Icon _tealIcon;
    private readonly Icon _redIcon;
    private readonly Icon _amberIcon;

    public event Action? OpenRequested;
    public event Action? QuickScanRequested;
    public event Action? DeepScanRequested;
    public event Action? ToggleRealtimeRequested;
    public event Action? ExitRequested;

    public TrayService()
    {
        _tealIcon = CreateShieldIcon(Color.FromArgb(27, 108, 128));  // #1B6C80 Petrol Teal
        _redIcon = CreateShieldIcon(Color.FromArgb(196, 36, 42));    // #C4242A Alert Crimson
        _amberIcon = CreateShieldIcon(Color.FromArgb(168, 111, 12)); // #A86F0C Paused Amber

        var menu = new WinForms.ContextMenuStrip();
        menu.Items.Add("Mở BaroAntivirus", null, (_, _) => OpenRequested?.Invoke());
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Quét Nhanh (Quick Scan)", null, (_, _) => QuickScanRequested?.Invoke());
        menu.Items.Add("Quét Sâu (DeepScan)", null, (_, _) => DeepScanRequested?.Invoke());
        _toggleRealtimeItem = new WinForms.ToolStripMenuItem("Tạm dừng Bảo vệ Thời gian thực", null, (_, _) => ToggleRealtimeRequested?.Invoke());
        menu.Items.Add(_toggleRealtimeItem);
        menu.Items.Add(new WinForms.ToolStripSeparator());
        menu.Items.Add("Thoát hoàn toàn", null, (_, _) => ExitRequested?.Invoke());

        _notifyIcon = new WinForms.NotifyIcon
        {
            Icon = _tealIcon,
            Text = "BaroAntivirus — Đang bảo vệ thời gian thực",
            Visible = true,
            ContextMenuStrip = menu
        };

        _notifyIcon.DoubleClick += (_, _) => OpenRequested?.Invoke();
    }

    public void UpdateStatus(bool realtimeEnabled, bool hasAlert, double ramMb)
    {
        _notifyIcon.Icon = hasAlert ? _redIcon : (realtimeEnabled ? _tealIcon : _amberIcon);
        string status = hasAlert
            ? "Cảnh báo mối nguy"
            : realtimeEnabled ? "Đang bảo vệ Real-time" : "Tạm dừng Real-time";
        string text = $"BaroAntivirus ({status}) | RAM: {ramMb:F1} MB";
        _notifyIcon.Text = text.Length > 63 ? text[..63] : text;
        _toggleRealtimeItem.Text = realtimeEnabled
            ? "Tạm dừng Bảo vệ Thời gian thực"
            : "Bật Bảo vệ Thời gian thực";
    }

    public void ShowNotification(string title, string message, bool isWarningOrError = false)
    {
        try
        {
            _notifyIcon.ShowBalloonTip(
                4500,
                title,
                message,
                isWarningOrError ? WinForms.ToolTipIcon.Warning : WinForms.ToolTipIcon.Info);
        }
        catch { }
    }

    private static Icon CreateShieldIcon(Color fillColor)
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);

            using var path = new GraphicsPath();
            path.AddPolygon(new[]
            {
                new Point(16, 2),
                new Point(29, 7),
                new Point(27, 19),
                new Point(16, 30),
                new Point(5, 19),
                new Point(3, 7)
            });

            using var brush = new SolidBrush(fillColor);
            g.FillPath(brush, path);

            using var checkPen = new Pen(Color.White, 2.6f)
            {
                StartCap = LineCap.Round,
                EndCap = LineCap.Round,
                LineJoin = LineJoin.Round
            };
            g.DrawLines(checkPen, new[]
            {
                new Point(10, 16),
                new Point(14, 20),
                new Point(22, 11)
            });
        }

        IntPtr hIcon = bmp.GetHicon();
        return Icon.FromHandle(hIcon);
    }

    public void Dispose()
    {
        _notifyIcon.Visible = false;
        _notifyIcon.Dispose();
        _tealIcon.Dispose();
        _redIcon.Dispose();
        _amberIcon.Dispose();
    }
}
