# Module 2: Wazuh SIEM — Manager, Dashboard & Endpoint Integration

## Mục tiêu

Dựng Wazuh SIEM (Manager + Indexer + Dashboard) làm trung tâm thu thập, phân tích log cho toàn bộ lab. Tích hợp Windows Server 2022 làm endpoint đầu tiên, cài Sysmon để có visibility ở tầng process/registry — nền tảng bắt buộc cho các module Detection Engineering sau này.

## Kiến trúc

| Thành phần | Vai trò | Cài trên |
|---|---|---|
| Wazuh Manager + Indexer + Dashboard | Thu thập, lưu trữ, hiển thị log/alert | Ubuntu 20.04 |
| Wazuh Agent | Gửi log từ endpoint về manager | Windows Server 2022 |
| Sysmon | Ghi log chi tiết process creation, network connection | Windows Server 2022 |

## 1. Cài đặt Wazuh Manager + Indexer + Dashboard trên Ubuntu Server

```terminal
curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh && sudo bash
./wazuh-install.sh -a -i
```
![Cấu hình](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/wazuh-siem/C%E1%BA%A5u%20h%C3%ACnh%20wazuh-manager.png)

![Wazuh-dashboard](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/wazuh-siem/Wazuh-dashboard.png)

## 2. Cài đặt Sysmon trên Windows Server 2022

Tải Sysmon và config cộng đồng SwiftOnSecurity (chuẩn phổ biến, cân bằng giữa độ chi tiết và nhiễu):

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
```

Cài đặt với config đã tải, sử dụng file XML tùy chỉnh:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

![Sysmon](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/wazuh-siem/sysmon.png)

## 3. Cài Wazuh Agent trên Windows Server qua Dashboard

Trên Wazuh Dashboard (Ubuntu manager) → **Endpoints Summary → Deploy new agent** → chọn Windows → dashboard sinh lệnh cài đặt, chạy trên PowerShell Administrator:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi -OutFile $env:tmp\wazuh-agent; msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='<WAZUH_MANAGER_IP>'
```

## 4. Trỏ Wazuh Agent đọc log Sysmon

Mở file cấu hình agent, thêm block `<localfile>` trỏ tới kênh Sysmon:

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

## 5. Cấu hình Windows ghi lại sự kiện logon (Event ID 4625)

Xác nhận Audit Policy đã bật ghi log cả Success lẫn Failure cho Logon, để Wazuh có thể phát hiện các lần đăng nhập thất bại (Event ID 4625) — nền tảng cho việc phát hiện brute-force sau này:

```powershell
auditpol /get /category:"Logon/Logoff"
```

Nếu chưa bật đủ, kích hoạt:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

![Xác nhận Event ID 4625 xuất hiện trên dashboard](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/wazuh-siem/Wazuh%20%C4%91%C3%A3%20ghi%20nh%E1%BA%ADn%20eventID%3D4625.png)

## Bảng tổng hợp vấn đề gặp phải

| Vấn đề | Nguyên nhân | Giải pháp |
|---|---|---|
| Không tìm thấy Event ID 4625 trên Wazuh dù đã đăng nhập sai nhiều lần | File `ossec.conf` mặc định của agent Windows không có sẵn block `<localfile>` đọc kênh `Security` | Thêm thủ công `<localfile><location>Security</location><log_format>eventchannel</log_format></localfile>` |
| Agent cài xong nhưng không "Active" trên dashboard | Lệnh `msiexec` bị nhầm tham số `WAZUH_MANAGER` thành hostname không resolve được thay vì IP thật | Sửa trực tiếp `<address>` trong `ossec.conf` thành đúng IP manager, restart service |

## Kết quả

- Wazuh Manager/Indexer/Dashboard hoạt động ổn định.
- Windows Server 2022 gửi log Security + Sysmon về thành công.
- Xác nhận pipeline end-to-end: tạo sự kiện đăng nhập sai → Wazuh alert Event ID 4625 hiển thị trên dashboard trong vòng vài chục giây.
