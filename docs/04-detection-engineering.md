# Module 4: Detection Engineering

## Mục tiêu

Viết custom Wazuh rule để phát hiện các kỹ thuật tấn công cụ thể, kiểm chứng bằng cách chủ động kích hoạt hành vi thật thông qua Atomic Red Team — thay vì chỉ viết rule lý thuyết, mỗi rule đều được test bằng dữ liệu thật và xác nhận alert nổ đúng trên dashboard.

## Công cụ

- **Atomic Red Team** — framework mô phỏng kỹ thuật MITRE ATT&CK bằng các test case nhỏ, độc lập.
- **Wazuh custom rules** (`local_rules.xml`) — viết rule XML dựa trên field từ log Sysmon.

## 1. T1059.001 — PowerShell EncodedCommand

Cài Atomic Red Team trên Windows Server 2022:

```powershell
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics
```

![Cài đặt Atomic Red Team](../screenshots/04-detection/atomicredteam-install.png)

Thực thi test T1059.001-17 (PowerShell Command Execution):

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 17
```

![Thực thi test PowerShell](../screenshots/04-detection/t1059-execution.png)

Kiểm tra log Sysmon ghi nhận đúng command line chạy dưới dạng encoded (`-e`):

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10 | Where-Object {$_.Id -eq 1} | Select-Object -First 1 -ExpandProperty Message
```

Log cho thấy `CommandLine: powershell.exe -e JgAgACgAZwBjAG0...` — xác nhận đúng kỹ thuật EncodedCommand mà kẻ tấn công thường dùng để né tránh phát hiện.

Viết custom rule trên manager (`sudo nano /var/ossec/etc/rules/local_rules.xml`):

```xml
<group name="local,windows,powershell,">
  <rule id="100010" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)powershell\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(-e |-enc |-EncodedCommand)</field>
    <description>Suspicious PowerShell execution with encoded command (T1059.001)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```

Restart manager, xác nhận trên Threat Hunting với truy vấn DQL `rule.id:100010`:

![Rule 100010 nổ thành công](../screenshots/04-detection/rule-100010-alert.png)

## 2. T1003 — Credential Dumping bằng Mimikatz

Thêm rule mới trên manager:

```xml
<group name="local,windows,credential_access,">
  <rule id="100011" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(mimikatz|sekurlsa|lsadump|privilege::debug|invoke-mimikatz)</field>
    <description>Possible Mimikatz execution detected - Credential Dumping (T1003)</description>
    <mitre>
      <id>T1003</id>
    </mitre>
  </rule>
</group>
```

Bật ghi log đầy đủ (`logall_json: yes`) trong `/var/ossec/etc/ossec.conf` để có thể debug bằng `archives.json` khi cần, restart manager.

Trên Windows Server, thực thi test Mimikatz (T1059.001-1) qua Atomic Red Team — tải và chạy `Invoke-Mimikatz -DumpCreds` (download cradle từ PowerSploit):

![Thực thi Mimikatz qua Atomic Red Team](../screenshots/04-detection/mimikatz-execution.png)

Quay lại dashboard, truy vấn `rule.id:100011`:

![Rule 100011 nổ thành công](../screenshots/04-detection/rule-100011-alert.png)

## 3. T1087 — Account Discovery (bổ sung ở module Incident Response)

Trong quá trình điều tra kịch bản IR (xem [module 6](../incident-reports/2026-07-26_ssh-bruteforce-victim.md)), phát hiện `auth.log` không ghi lại nội dung lệnh sau khi đăng nhập — cần bổ sung `auditd` để có visibility tương đương Sysmon trên Linux, và viết thêm rule `100014` cho hành vi `cat /etc/passwd`. Chi tiết đầy đủ nằm trong báo cáo Incident Response.

## Bảng tổng hợp vấn đề gặp phải

| Vấn đề | Nguyên nhân | Giải pháp |
|---|---|---|
| Rule không nổ dù đã "lưu" file | Thoát `nano` mà không xác nhận save (Ctrl+O → Enter) trước khi Ctrl+X | Luôn `cat` lại file để xác nhận nội dung đã lưu trước khi restart manager |
| Cài `AtomicTestHarnesses` module bị chặn: *"file contains a virus"* | Windows Defender nhận diện nhầm code giả lập tấn công là malware | Chuyển sang test case khác không cần module phụ trợ (T1059.001-17 thay vì -15), hoặc tắt tạm Realtime Protection |
| `wazuh-logtest` không match rule dù dùng đúng field | JSON test tay tự viết thiếu field mà decoder Sysmon cần (`channel`, `computer`...) | Lấy JSON thật từ `archives.json` thay vì tự viết tay khi debug |

## MITRE ATT&CK Coverage từ module này

| Technique | Rule ID | Level |
|---|---|---|
| T1059.001 — PowerShell | 100010 | 12 |
| T1003 — OS Credential Dumping | 100011 | 15 |
