# SOC Home Lab

Home lab mô phỏng môi trường Security Operations Center (SOC) thực tế, xây dựng trên VMware Workstation với ngân sách phần cứng hạn chế (~120GB ổ đĩa). Lab tập trung vào 3 trụ cột: **Detection Engineering**, **Threat Hunting**, và **Incident Response** — thay vì chỉ dừng lại ở việc cài đặt công cụ, mỗi module đều có kịch bản tấn công thật, bằng chứng phát hiện thật, và quy trình debug thật.

---

## Kiến trúc lab

```
                        ┌─────────────────────────┐
                        │   Wazuh Manager (Ubuntu) │
                        │   SIEM - Indexer/Dashboard│
                        └────────────┬─────────────┘
                                     │ agent logs
              ┌──────────────────────┼──────────────────────┐
              │                      │                      │
    ┌─────────▼─────────┐  ┌────────▼──────────┐  ┌─────────▼─────────┐
    │  Windows Server    │  │  Ubuntu Victim     │  │   Metasploitable2  │
    │  2022               │  │  + Suricata (NIDS) │  │   (unmonitored     │
    │  + Sysmon (HIDS)    │  │  + auditd (HIDS)   │  │   target)           │
    └─────────────────────┘  └────────────────────┘  └─────────────────────┘
              ▲                      ▲                      ▲
              └──────────────────────┴──────────────────────┘
                                     │
                        ┌────────────┴─────────────┐
                        │      Kali Linux            │
                        │      (Attacker)             │
                        └─────────────────────────────┘
```

Mạng lab chạy trên VMware Custom VMnet (subnet cô lập `10.2.66.0/24`), tách biệt hoàn toàn khỏi mạng nhà.

## Thành phần

| Thành phần | Vai trò | Công nghệ |
|---|---|---|
| SIEM | Thu thập, phân tích, tương quan log | Wazuh 4.12 (Manager + Indexer + Dashboard) |
| NIDS | Giám sát traffic mạng | Suricata 8.0.6 |
| HIDS (Windows) | Giám sát process/registry | Sysmon (SwiftOnSecurity config) |
| HIDS (Linux) | Giám sát command execution | auditd |
| Attacker | Mô phỏng red team | Kali Linux |
| Victim - Windows | Endpoint giám sát | Windows Server 2022 |
| Victim - Linux | Endpoint giám sát + NIDS sensor | Ubuntu 20.04 |
| Target | Máy dễ tổn thương (network/service) | Metasploitable2 |
| Target | Máy dễ tổn thương (web app) | DVWA, OWASP Juice Shop (Docker) |
| Simulation | Giả lập kỹ thuật MITRE ATT&CK | Atomic Red Team |

## Điểm nổi bật

- **3 custom Wazuh detection rule** tự viết, mỗi rule đều được kiểm chứng bằng cách kích hoạt hành vi thật (không chỉ viết rule suông):
  - `100010` — Phát hiện PowerShell EncodedCommand (T1059.001)
  - `100011` — Phát hiện Mimikatz credential dumping (T1003)
  - `100014` — Phát hiện truy cập file nhạy cảm qua `cat` (T1087)
- **Full attack chain hoàn chỉnh**: Network recon (nmap) → Exploitation (Metasploit vsftpd 2.3.4 backdoor RCE) → Web exploitation (SQL Injection trên DVWA) → Brute-force (Hydra SSH) → Post-exploitation → Detection → Containment.
- **1 kịch bản Incident Response đầy đủ**: từ alert ban đầu, điều tra pivot theo IP, xác nhận cross-source (HIDS + NIDS), tới containment và báo cáo chính thức.
- **MITRE ATT&CK Coverage Matrix**: 9 techniques được map và verify, phủ 5 tactic (Initial Access, Execution, Discovery, Credential Access, Persistence).
- **Quá trình debug thực tế được ghi lại đầy đủ** — network mất IP, password sync giữa Dashboard/Indexer, sai interface Suricata, decoder audit bị nhầm nguồn (`journald` vs file thật)... Đây là phần phản ánh đúng nhất kỹ năng troubleshooting thực chiến.

## Cấu trúc repo

```
soc-home-lab/
├── README.md
├── docs/                      # Chi tiết từng module
│   ├── 01-network-foundation.md
│   ├── 02-wazuh-siem.md
│   ├── 03-kali-metasploitable.md
│   ├── 04-detection-engineering.md
│   ├── 05-nids-suricata.md
│   ├── 06-incident-response.md
│   └── 07-attack-navigator.md
├── wazuh-rules/
│   └── local_rules.xml        # Toàn bộ custom rule
├── incident-reports/
│   └── 2026-07-26_ssh-bruteforce-victim.md
├── attack-navigator/
│   ├── coverage-matrix.json   # Layer export từ ATT&CK Navigator
│   └── coverage-matrix.svg
├── screenshots/                # Bằng chứng theo từng module
└── network-diagram.png
```

## Modules

| # | Module | Nội dung chính |
|---|---|---|
| 1 | [Network Foundation](docs/01-network-foundation.md) | VMware Custom VMnet, subnet cô lập 10.2.66.0/24 |
| 2 | [Wazuh SIEM](docs/02-wazuh-siem.md) | Cài đặt Manager/Indexer/Dashboard, tích hợp Windows/Linux agent, Sysmon |
| 3 | [Kali + Metasploitable2](docs/03-kali-metasploitable.md) | Nmap recon, Metasploit RCE (vsftpd backdoor), Hydra brute-force, SQLi trên DVWA |
| 4 | [Detection Engineering](docs/04-detection-engineering.md) | Viết & test custom Wazuh rule bằng Atomic Red Team |
| 5 | [NIDS - Suricata](docs/05-nids-suricata.md) | Suricata trên Linux victim, tích hợp eve.json vào Wazuh |
| 6 | [Incident Response](docs/06-incident-response.md) | Kịch bản SSH brute-force đầy đủ: detect → investigate → contain → report |
| 7 | [ATT&CK Navigator](docs/07-attack-navigator.md) | Coverage matrix, phân tích detection gap |

## MITRE ATT&CK Coverage

| Technique | Tactic | Rule/Bằng chứng |
|---|---|---|
| T1046 - Network Service Discovery | Discovery | Nmap scan |
| T1190 - Exploit Public-Facing Application | Initial Access | Metasploit vsftpd 2.3.4 RCE |
| T1110.001 - Brute Force | Credential Access | Hydra SSH |
| T1078 - Valid Accounts | Initial Access/Persistence | SSH login sau brute-force |
| T1003 - OS Credential Dumping | Credential Access | Wazuh rule 100011 (Mimikatz) |
| T1059.001 - PowerShell | Execution | Wazuh rule 100010 (EncodedCommand) |
| T1087 - Account Discovery | Discovery | Wazuh rule 100014 (`cat /etc/passwd`) |
| T1069 - Permission Groups Discovery | Discovery | `sudo -l` |
| T1057 - Process Discovery | Discovery | Wazuh default rule 92604 |

Xem chi tiết heat map tại [`attack-navigator/coverage-matrix.svg`](attack-navigator/coverage-matrix.svg).

## Công nghệ sử dụng

`VMware Workstation` `Wazuh 4.12` `Suricata 8.0.6` `Sysmon` `auditd` `Kali Linux` `Metasploit Framework` `Hydra` `Nmap` `DVWA` `OWASP Juice Shop` `Atomic Red Team` `MITRE ATT&CK Navigator`

## Ghi chú

Toàn bộ lab chạy trong mạng ảo cô lập, không kết nối/ảnh hưởng tới hệ thống thật nào. Mọi IP, hostname, credential xuất hiện trong repo đều thuộc phạm vi lab nội bộ, không phải thông tin nhạy cảm.

---

*Lab được xây dựng nhằm mục đích học tập, luyện tập kỹ năng SOC Analyst và xây dựng portfolio.*
