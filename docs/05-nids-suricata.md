# Module 5: NIDS — Suricata

## Mục tiêu

Triển khai Suricata làm Network Intrusion Detection System (NIDS) trên Ubuntu victim, bổ sung khả năng giám sát ở tầng network bên cạnh HIDS (Wazuh agent) đã có — cho phép phát hiện traffic tấn công ngay cả khi máy đích không có agent (ví dụ Metasploitable2), và tích hợp alert vào cùng 1 dashboard Wazuh trung tâm.

## Vì sao đặt Suricata trên máy Victim thay vì máy Attacker

Về mặt kiến trúc, NIDS cần đứng ở vị trí quan sát traffic hướng tới hệ thống cần bảo vệ — đặt trên Kali (máy tấn công) chỉ thấy được traffic do chính nó tạo ra, không đúng vai trò Defender. Suricata được cài trên Ubuntu victim để đóng đúng vai trò giám sát traffic đến/đi từ endpoint cần bảo vệ.

## 1. Cài đặt Suricata

Package `suricata` không có sẵn trong repo mặc định Ubuntu 20.04 — cần thêm PPA chính thức của OISF (Open Information Security Foundation):

```bash
sudo apt install -y software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata
```

![Cài đặt Suricata](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/NIDS-suricata/c%C3%A0i%20suricata%20th%C3%A0nh%20c%C3%B4ng.png)

## 2. Cấu hình đúng interface mạng lab

Xác định card mạng thật (dải VMnet2, không phải card NAT):

```bash
ip a
```

Sửa cấu hình để Suricata lắng nghe đúng interface (mặc định file trỏ tới `eth0`, cần đổi thành tên interface thật):

```bash
sudo sed -i 's/eth0/ens37/g' /etc/suricata/suricata.yaml
```

![Sed thay đổi interface](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/NIDS-suricata/Config%20l%E1%BA%A1i%20suricata.png)

## 3. Cài rule mặc định và khởi động

```bash
sudo suricata-update
sudo systemctl restart suricata
sudo systemctl status suricata
```

Xác nhận trạng thái `active (running)`.

## 4. Kiểm chứng — tạo traffic test

Trên Ubuntu victim, mở listener:

```bash
nc -lvnp 4444
```

Từ Kali, gửi 1 chuỗi test qua kết nối TCP thô:

```bash
echo "uid=0(root) gid=0(root) groups=0(root)" | nc -n 10.2.66.137 4444
```

Kết nối thành công, nội dung nhận đúng.

Tiếp tục tạo thêm traffic thật bằng brute-force và network scan:

```bash
hydra -l victim -P /tmp/small_wordlist.txt ssh://10.2.66.137
sudo nmap -sV -sC -A 10.2.66.137
```

Kiểm tra `fast.log` trên victim, xác nhận 2 loại alert đã nổ:

```
[**] [1:2100498:7] GPL ATTACK_RESPONSE id check returned root [**]
[**] [1:2200025:2] SURICATA ICMPv4 unknown code [**]
```

![Alert Suricata trong fast.log](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/NIDS-suricata/x%C3%A1c%20nh%E1%BA%ADn%20suricata%20ho%E1%BA%A1t%20%C4%91%E1%BB%99ng%20th%C3%A0nh%20c%C3%B4ng.png)

## 5. Cài Wazuh Agent trên Ubuntu victim

Trên Dashboard (Ubuntu manager) → **Endpoints Summary → Deploy new agent** → chọn Linux (deb) → copy lệnh cài, chạy trên victim → cấu hình `ossec.conf` trỏ đúng địa chỉ manager, khởi động:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

Xác nhận `active (running)` và agent hiện "Active" trên dashboard.

## 6. Tích hợp log Suricata vào Wazuh (eve.json)

Thêm `<localfile>` đọc file JSON đầy đủ của Suricata (không chỉ `fast.log`):

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

Restart agent, tạo lại traffic test (nmap từ Kali), sau đó trên dashboard vào **Threat Hunting**, truy vấn:

```
data.alert.signature:*
```

![Alert Suricata hợp nhất trên Wazuh Dashboard](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/NIDS-suricata/Suricata%20tr%C3%AAn%20wazuh.png)

## Bảng tổng hợp vấn đề gặp phải

| Vấn đề | Nguyên nhân | Giải pháp |
|---|---|---|
| `apt install suricata` báo "no installation candidate" | Package không có sẵn trong repo mặc định Ubuntu 20.04 | Thêm PPA chính thức `ppa:oisf/suricata-stable` |
| Service `suricata` liên tục restart-fail | File cấu hình mặc định trỏ sai interface (`eth0` thay vì `ens37`) | `sed -i 's/eth0/ens37/g'` toàn bộ file config |
| `fast.log` trống dù traffic đã đi qua (counter tăng bình thường) | Có traffic ≠ có alert — rule engine chỉ tạo alert khi signature khớp, "packet captured" khác với "alert matched" | Dùng traffic tấn công thật (Hydra, nmap) thay vì chuỗi test tùy ý để có khả năng khớp rule cao hơn |
| Tìm alert trên dashboard theo field `data.srcip` không ra kết quả cho alert Suricata | Wazuh HIDS (auth.log) và Suricata (eve.json) dùng tên field IP nguồn khác nhau | Kết hợp cả 2 field khi search, hoặc tìm bằng full-text (không chỉ định field) |

## Kết quả

Suricata hoạt động ổn định, alert được tích hợp hoàn chỉnh vào Wazuh Dashboard — hệ thống giờ có cả HIDS (Wazuh agent + Sysmon/auditd) lẫn NIDS (Suricata) phối hợp, đúng kiến trúc SOC thực tế.
