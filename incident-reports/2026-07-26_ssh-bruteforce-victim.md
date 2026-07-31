# Incident Report: SSH Brute-Force Attack on victim-virtual-machine

**Người điều tra:** [Tên bạn]
**Ngày xảy ra sự cố:** 26/07/2026
**Ngày viết báo cáo:** 26/07/2026
**Mức độ nghiêm trọng:** Cao (brute-force thành công, kẻ tấn công có được shell với quyền sudo ALL)

---

## 1. Tóm tắt (Executive Summary)

Ngày 26/07/2026, hệ thống SIEM (Wazuh) ghi nhận nhiều alert xác thực thất bại (`authentication_failed`) nhắm vào máy chủ Linux nội bộ `victim-virtual-machine` (10.2.66.137) từ nguồn `10.2.66.135`. Điều tra xác nhận đây là tấn công brute-force SSH sử dụng công cụ Hydra, và kẻ tấn công đã **tìm ra mật khẩu hợp lệ** cho tài khoản `victim`, sau đó đăng nhập thành công và thực hiện các lệnh trinh sát hệ thống. Đã tiến hành containment bằng cách chặn IP nguồn qua `ufw`.

## 2. Phạm vi ảnh hưởng (Scope)

| Mục | Chi tiết |
|---|---|
| Hệ thống bị ảnh hưởng | victim-virtual-machine (10.2.66.137) |
| Tài khoản bị xâm phạm | victim |
| Nguồn tấn công | 10.2.66.135 (Kali — trong bài tập này) |
| Dữ liệu bị truy cập | /etc/passwd (danh sách user hệ thống) |
| Quyền kẻ tấn công đạt được | sudo ALL (toàn quyền root) |

## 3. Timeline

| Thời gian (giờ:phút) | Sự kiện |
|---|---|
| [điền giờ] | Hydra bắt đầu brute-force SSH từ 10.2.66.135 |
| [điền giờ] | Hydra xác định mật khẩu đúng |
| [điền giờ] | Đăng nhập SSH thành công từ 10.2.66.135, giả lập hành vi kẻ tấn công đăng nhập trái phép |
| [điền giờ] | Kẻ tấn công chạy các lệnh trinh sát: `whoami`, `sudo -l`, `cat /etc/passwd` |
| [điền giờ] | Wazuh Dashboard phát hiện qua truy vấn `rule.groups:*authentication*`, xác nhận đăng nhập thành công |
| [điền giờ] | Suricata trigger alert tương ứng với traffic từ nguồn tấn công |
| [điền giờ] | Containment: chặn IP `10.2.66.135` qua Uncomplicated Firewall (ufw) trên victim |
| [điền giờ] | Xác nhận containment: kết nối SSH tiếp theo từ máy tấn công bị chặn thành công |
| [điền giờ] | Bổ sung giám sát: cấu hình `auditd` + custom rule để phát hiện lệnh trinh sát sau đăng nhập |

## 4. Phát hiện (Detection)

- **Nguồn phát hiện 1 — Wazuh (HIDS):** đọc log `/var/log/auth.log`, truy vấn DQL `rule.groups:*authentication*` trên Threat Hunting trả về loạt alert xác thực thất bại liên tiếp từ cùng 1 IP, sau đó là alert đăng nhập thành công.

  ![Wazuh dashboard phát hiện brute-force](../screenshots/06-ir/wazuh-auth-alerts.png)

- **Nguồn phát hiện 2 — Suricata (NIDS):** ghi nhận traffic bất thường từ 10.2.66.135, alert hiện song song trên cùng dashboard nhờ tích hợp `eve.json` (xem [module 5](../docs/05-nids-suricata.md)).

  ![Suricata alert tương ứng](../screenshots/06-ir/suricata-alert.png)

- **Ghi chú kỹ thuật quan trọng:** ban đầu, log `auth.log` chỉ ghi lại được sự kiện xác thực (login/logout/sudo), **không ghi lại nội dung lệnh** kẻ tấn công gõ sau khi đăng nhập thành công (`cat /etc/passwd` không để lại dấu vết trong nguồn log này). Đây là khoảng trống phát hiện (detection gap) tương tự việc thiếu Sysmon trên Windows.

## 5. Điều tra (Investigation)

- Xác nhận qua `auth.log` trên chính victim: nhiều dòng `Failed password for victim from 10.2.66.135`, sau đó `Accepted password`.
- Kẻ tấn công đăng nhập SSH bằng mật khẩu vừa brute-force được, thực hiện các lệnh trinh sát điển hình: `whoami` (xác định danh tính), `sudo -l` (kiểm tra quyền hạn), `cat /etc/passwd` (liệt kê tài khoản hệ thống) — phù hợp với giai đoạn **Discovery** trong MITRE ATT&CK (T1087 - Account Discovery, T1069 - Permission Groups Discovery).
- Phát hiện quyền hạn tài khoản `victim` là `(ALL : ALL) ALL` — rủi ro nghiêm trọng, tài khoản có toàn quyền root nếu bị chiếm đoạt.
- **Lấp khoảng trống phát hiện:** để giám sát được hành vi sau đăng nhập, cấu hình bổ sung `auditd` (tương đương Sysmon trên Linux) để ghi lại mọi lệnh thực thi (`execve` syscall), trỏ Wazuh agent đọc `/var/log/audit/audit.log`, và viết custom rule mới (`100014`, level 10) để nâng mức độ nghiêm trọng cho hành vi truy cập file nhạy cảm — mặc định Wazuh gộp các sự kiện audit vào 1 rule chung level 0, không tự động hiển thị alert nếu không có rule riêng.
- Sau khi bổ sung, truy vấn `data.audit.command:*` trên Threat Hunting trả về đầy đủ các lệnh kẻ tấn công đã thực thi.

  ![Custom rule 100014 phát hiện cat /etc/passwd](../screenshots/06-ir/rule-100014-audit.png)

## 6. Containment (Ngăn chặn)

Trên victim-virtual-machine, chặn địa chỉ IP tấn công qua Uncomplicated Firewall:

```bash
sudo ufw enable
sudo ufw reject from 10.2.66.135 to any
sudo ufw status
```

![Cấu hình chặn qua ufw](../screenshots/06-ir/ufw-block.png)

Xác nhận hiệu quả từ phía máy tấn công — kết nối SSH tiếp theo bị từ chối/timeout ngay lập tức.

![Xác nhận kết nối bị chặn từ Kali](../screenshots/06-ir/kali-blocked.png)

**Lưu ý kỹ thuật:** ban đầu dùng `ufw deny` (âm thầm DROP gói tin), khiến việc xác nhận containment mất nhiều thời gian do phải chờ TCP timeout. Chuyển sang `ufw reject` (gửi phản hồi từ chối ngay lập tức) giúp xác nhận nhanh và rõ ràng hơn.

## 7. Nguyên nhân gốc (Root Cause)

- Mật khẩu tài khoản `victim` quá yếu, dễ dàng bị brute-force chỉ với vài lần thử bằng wordlist nhỏ.
- SSH cho phép xác thực bằng mật khẩu, không giới hạn số lần thử sai, không có công cụ rate-limiting (như fail2ban).
- Tài khoản có quyền sudo ALL không cần thiết cho vai trò của nó.
- Cấu hình giám sát ban đầu (chỉ dựa vào `auth.log`) có khoảng trống, không thấy được hành vi sau khi kẻ tấn công đã có shell.

## 8. Khuyến nghị (Recommendations)

1. Áp dụng chính sách mật khẩu mạnh, tối thiểu 12 ký tự, kết hợp chữ hoa/thường/số/ký tự đặc biệt.
2. Chuyển sang xác thực bằng SSH key, tắt hẳn `PasswordAuthentication` trong `sshd_config`.
3. Triển khai `fail2ban` để tự động khóa IP sau N lần đăng nhập sai.
4. Giới hạn quyền sudo theo nguyên tắc least privilege, không cấp `ALL:ALL` cho tài khoản thông thường.
5. Duy trì `auditd` trên các endpoint Linux quan trọng để có visibility đầy đủ ở tầng command execution, tương tự vai trò Sysmon trên Windows.

## 9. Ánh xạ MITRE ATT&CK

| Kỹ thuật | Technique ID | Giai đoạn |
|---|---|---|
| Brute Force | T1110.001 | Credential Access |
| Valid Accounts | T1078 | Initial Access / Persistence |
| Account Discovery | T1087 | Discovery |
| Permission Groups Discovery | T1069 | Discovery |

---

*Báo cáo này là một phần của SOC Home Lab — mục đích học tập và xây dựng portfolio, thực hiện trong môi trường lab cô lập.*
