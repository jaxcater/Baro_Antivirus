# BaroAntivirus

Phần mềm **Antivirus, quét virus & mã độc chuyên sâu (`DeepScan`)** và bảo vệ thời gian thực siêu nhẹ dành cho Windows 10/11 (x64).



---

## Hai phiên bản phát hành (Releases)

Tải về tại trang **[GitHub Releases](https://github.com/jaxcater/Baro_Antivirus/releases)**:

1. **Windows Installer (`Baro_setup.exe`)** — Bản cài đặt hoàn chỉnh vào Windows:
   - Tích hợp trình cài đặt & gỡ cài đặt chuẩn Windows (**Add/Remove Programs**).
   - Tự tạo lối tắt Desktop, Start Menu và tùy chọn tự khởi chạy bảo vệ nền cùng Windows (`--minimized`).
2. **Windows Portable (`BaroAntivirus-Portable-win-x64.zip`)** — Bản di động không cần cài đặt:
   - Giải nén và chạy trực tiếp `BaroAntivirus.exe` (tích hợp sẵn runtime `.NET 9`, chạy trên mọi máy Windows 10/11 x64).

---

## Tính năng bảo vệ nổi bật

### 1. Chặt chẽ hơn Windows Defender (Multi-Engine Detection)
- **Download Guard & Kiểm tra nguồn gốc Internet**: Đọc NTFS `:Zone.Identifier` (`ZoneId=3`) kết hợp xác minh chữ ký số **Authenticode (`WinVerifyTrust`)**. Ở chế độ mặc định **`Strict`** (hoặc `Paranoid`), tệp thực thi tải từ Internet chưa ký số có dấu hiệu bất thường sẽ bị chặn và cách ly ngay trước khi người dùng mở.
- **DeepScan Đa Tầng**:
  - **PE32/PE64 Structural & API Analyzer**: Tự phân tích header PE, phát hiện section vừa ghi vừa thực thi (`RWX`), Packer (`UPX`, `VMProtect`, `Themida`, `MPRESS`), Shannon Entropy cao ($\ge 7.2$), PE Overlay ẩn và tổ hợp API nguy hiểm (`VirtualAllocEx + WriteProcessMemory + CreateRemoteThread`, Process Hollowing `NtUnmapViewOfSection`, Keylogger).
  - **Script, Shortcut (`.lnk`) & Giả mạo tên tệp**: Bắt giả mạo phần mở rộng kép (`invoice.pdf.exe`), ký tự đảo chiều Unicode RLO (`\u202E`), làm rối PowerShell (`-EncodedCommand`, `FromBase64String`, `IEX`), HTML Smuggling và shortcut `.lnk` ẩn lệnh shell.
  - **Archive Inspector (`.zip`)**: Quét trực tiếp trong bộ nhớ không giải nén ra đĩa, phát hiện Zip Bomb, file thực thi đặt mật khẩu né trình quét và script độc hại bên trong.
  - **Signature & YARA-style Rules**: SHA-256 blocklist, chuẩn EICAR, phát hiện xóa Shadow Copy (`vssadmin`), đánh cắp thông tin LSASS/trình duyệt, AMSI bypass, Reverse Shell, LOLBins và CryptoMiner.

### 2. Luôn chạy cùng người dùng & Siêu nhẹ > Windows Defender
- **System Tray (`NotifyIcon`)**: Tự thu nhỏ xuống khay hệ thống khi đóng cửa sổ (`X`), cảnh báo tức thì qua thông báo Windows, hỗ trợ Single-Instance `Mutex` và tự khởi động cùng Windows (`--minimized`).
- **Tối ưu tài nguyên chạy nền**: Dùng `ServerGarbageCollection=false`, luồng quét `ThreadPriority.BelowNormal`, giới hạn concurrency, đọc stream đệm (`SequentialScan`) và cắt giảm bộ nhớ `SetProcessWorkingSetSizeEx` khi chạy nền (~`33–38 MB RAM`, nhẹ hơn nhiều so với mức ~`150–300 MB` thường thấy ở `MsMpEng.exe`).

### 3. Các công cụ An toàn mở rộng
- **Lá chắn Thời gian thực (`FileSystemWatcher`)**: Bảo vệ `Downloads`, `Desktop`, `Documents`, `Temp`, `Startup` và tự đợi trình duyệt tải hoàn tất (`.crdownload`, `.part`, `.tmp`).
- **Chống Ransomware Thư mục**: Phát hiện đổi tên/sửa tệp hàng loạt bất thường hoặc phần mở rộng mã hóa (`.locked`, `.encrypted`, `.lockbit`...).
- **Lá chắn Mạng & Chống Lừa đảo**: Kiểm tra URL lừa đảo (giả mạo thương hiệu/ngân hàng, Punycode `xn--`, IP trực tiếp, `@` credential trick), cảnh báo liên kết nguy hiểm trong Clipboard, theo dõi kết nối TCP theo PID (`GetExtendedTcpTable`) và tùy chọn chặn domain qua tệp `hosts` (khi chạy quyền Admin).
- **Giám sát Tiến trình & Khởi động (`Process & Startup Guard`)**: Phát hiện giả mạo `svchost.exe`/`lsass.exe` ngoài thư mục Windows, tiến trình chạy từ `Temp`/`Downloads` và kiểm toán các mục Registry/Startup.
- **USB Shield**: Tự động quét ổ USB mới cắm (`autorun.inf`, shortcut, tệp thực thi).
- **Khu Cách Ly Mã hóa AES-256-GCM**: Tách biệt an toàn, hỗ trợ Khôi phục (+ Whitelist) hoặc Xóa vĩnh viễn.
- **Secure File Shredder**: Ghi đè 3 lớp (`0x00`, `0xFF`, ngẫu nhiên) trước khi xóa.

---

## Tự Build từ mã nguồn

Yêu cầu **.NET 9 SDK** trên Windows:

```powershell
# Build toàn bộ giải pháp
dotnet build BaroAntivirus.sln -c Release

# Chạy bộ kiểm thử tự động (10 test suites)
dotnet run --project tests\BaroAntivirus.Tests\BaroAntivirus.Tests.csproj -c Release

# Đóng gói bản cài đặt Baro_setup.exe
powershell -ExecutionPolicy Bypass -File build-setup.ps1
```
