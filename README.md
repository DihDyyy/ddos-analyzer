# 🛡️ Hệ thống Giám sát An toàn Mạng - DDoS Analyzer

> Công cụ giám sát mạng thời gian thực và phân tích file `.pcap` để phát hiện tấn công DDoS tầng 3, 4, 7.
> Thiết kế theo hướng SOC/Blue Team phục vụ đồ án An toàn thông tin.

## 🎯 Tính năng chính

### 📡 Chế độ 1: Giám sát thời gian thực (Live Monitor)
| Tính năng | Chi tiết |
|---|---|
| **Bắt gói tin trực tiếp** | Sử dụng `tshark` (Wireshark CLI) để sniff trên card mạng |
| **Dashboard real-time** | Cập nhật biểu đồ PPS, giao thức, cảnh báo mỗi 1.5 giây |
| **Phát hiện DDoS tức thì** | Cảnh báo ngay khi phát hiện SYN/UDP/ICMP/HTTP Flood |
| **Chọn card mạng** | Hỗ trợ eth0, wlan0, hoặc bất kỳ interface nào |
| **Không cần file .pcap** | Giám sát trực tiếp, không cần lưu file trước |

### 📂 Chế độ 2: Phân tích file PCAP
| Tính năng | Chi tiết |
|---|---|
| **Upload file .pcap** | Kéo thả hoặc chọn file từ Wireshark |
| **Phân tích giao thức** | TCP, UDP, ICMP, HTTP (Layer 3/4/7) |
| **Phát hiện tấn công** | SYN Flood, UDP Flood, ICMP Flood, HTTP Flood |
| **Thống kê IP** | Top source IPs với phân bố giao thức và đánh giá rủi ro |
| **Báo cáo** | Xuất JSON và CSV (alerts, top IPs, statistics) |

### Chung
| Tính năng | Chi tiết |
|---|---|
| **Tốc độ Packet** | Biểu đồ PPS (packets/second) real-time |
| **Cảnh báo** | Alerts với severity: CRITICAL / HIGH / MEDIUM / LOW |
| **Web Dashboard** | Giao diện web hiện đại, dark theme, Chart.js |
| **CLI Dashboard** | Giao diện terminal với Rich (màu sắc, bảng) |

## 📋 Yêu cầu hệ thống

- **Python** >= 3.8
- **Kali Linux** (khuyến nghị) / Ubuntu / Windows / macOS
- **tshark** (đi kèm khi cài Wireshark) — cần cho chế độ Live Monitor
- **Quyền root/sudo** — cần để bắt gói tin trên card mạng

## 🚀 Cài đặt trên Kali Linux

```bash
# 1. Clone/tải về thư mục dự án
cd ~/giamsatantoanmang

# 2. Cài đặt thư viện Python
pip install -r requirements.txt --break-system-packages

# 3. Kiểm tra tshark đã cài chưa
tshark --version

# 4. Nếu chưa có tshark:
sudo apt update && sudo apt install -y tshark
```

## 📖 Cách sử dụng

### Chạy Web Dashboard (khuyến nghị)

```bash
# Chạy với quyền root để bắt gói tin
sudo python3 app.py
```

Mở trình duyệt tại: **http://localhost:5000**

#### Chế độ Live Monitor:
1. Chọn tab **📡 Giám sát Thời gian thực**
2. Chọn card mạng (eth0, wlan0, ...)
3. Tùy chỉnh ngưỡng phát hiện nếu cần
4. Nhấn **"Bắt đầu giám sát"**
5. Dashboard tự động cập nhật, cảnh báo hiện ngay khi phát hiện tấn công

#### Chế độ PCAP:
1. Chọn tab **📂 Phân tích File PCAP**
2. Kéo thả file .pcap vào vùng upload
3. Nhấn **"Bắt đầu phân tích"**
4. Xem kết quả và tải báo cáo

### Chạy CLI (dòng lệnh)

```bash
# Phân tích file pcap
sudo python3 main.py capture.pcap

# Tùy chỉnh ngưỡng
sudo python3 main.py capture.pcap --syn-threshold 50 --udp-threshold 100

# Chỉ xuất JSON report
sudo python3 main.py capture.pcap --format json

# Chỉ định thư mục output
sudo python3 main.py capture.pcap --output-dir ./my_reports
```

## ⚙️ Cấu hình ngưỡng phát hiện

Các ngưỡng mặc định trong `config.py`:

| Tấn công | Ngưỡng mặc định | Ý nghĩa |
|---|---|---|
| SYN Flood | 100 pkt/s | TCP SYN packets/giây từ 1 IP |
| UDP Flood | 200 pkt/s | UDP packets/giây từ 1 IP |
| ICMP Flood | 50 pkt/s | ICMP packets/giây từ 1 IP |
| HTTP Flood | 50 req/s | HTTP requests/giây từ 1 IP |

> 💡 Có thể tùy chỉnh ngưỡng trực tiếp trên giao diện web trước khi bắt đầu giám sát.

### Mức độ cảnh báo (Severity)

| Mức độ | Tỷ lệ so với ngưỡng |
|---|---|
| 🔵 LOW | >= 1x |
| 🟡 MEDIUM | >= 2x |
| 🟠 HIGH | >= 5x |
| 🔴 CRITICAL | >= 10x |

## 📁 Cấu trúc dự án

```
giamsatantoanmang/
├── app.py                   # Web server (Flask) - Live Monitor + PCAP
├── main.py                  # CLI interface
├── config.py                # Cấu hình ngưỡng phát hiện
├── requirements.txt         # Thư viện Python
├── README.md                # Hướng dẫn sử dụng
├── analyzer/                # Package phân tích
│   ├── __init__.py
│   ├── live_sniffer.py      # ⭐ Bắt gói tin real-time (tshark)
│   ├── packet_parser.py     # Đọc & parse file pcap (Scapy)
│   ├── statistics.py        # Thống kê traffic
│   ├── detector.py          # Engine phát hiện DDoS
│   ├── dashboard.py         # CLI Dashboard (Rich)
│   └── reporter.py          # Xuất báo cáo JSON/CSV
├── templates/
│   └── index.html           # Giao diện web
├── static/
│   ├── css/style.css        # Giao diện dark theme
│   └── js/app.js            # Frontend logic
├── uploads/                 # File upload tạm
└── reports/                 # Báo cáo xuất ra
```

## 🔍 Phương pháp phát hiện

### SYN Flood (Layer 4)
- **Nguyên lý**: Đếm TCP SYN packets (không có ACK) từ mỗi source IP mỗi giây
- **Dấu hiệu**: Lượng SYN packets/giây từ 1 IP vượt ngưỡng
- **Mục đích tấn công**: Làm cạn kiệt bảng kết nối của server

### UDP Flood (Layer 4)
- **Nguyên lý**: Đếm UDP packets từ mỗi source IP mỗi giây
- **Dấu hiệu**: Lượng UDP packets/giây từ 1 IP vượt ngưỡng
- **Mục đích tấn công**: Gây nghẽn bandwidth với traffic UDP

### ICMP Flood (Layer 3)
- **Nguyên lý**: Đếm ICMP packets (ping) từ mỗi source IP mỗi giây
- **Dấu hiệu**: Lượng ICMP packets/giây từ 1 IP vượt ngưỡng
- **Mục đích tấn công**: Gây nghẽn bandwidth bằng ICMP Echo Request

### HTTP Flood (Layer 7)
- **Nguyên lý**: Đếm HTTP requests (GET, POST) từ mỗi source IP mỗi giây
- **Dấu hiệu**: Lượng HTTP requests/giây từ 1 IP vượt ngưỡng
- **Mục đích tấn công**: Quá tải web server với requests hợp lệ

## 🛠️ Công nghệ sử dụng

| Công nghệ | Mục đích |
|---|---|
| [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) | Bắt gói tin thời gian thực (Live Monitor) |
| [Scapy](https://scapy.net/) | Đọc file pcap, phân tích packet |
| [Flask](https://flask.palletsprojects.com/) | Web server backend |
| [Chart.js](https://www.chartjs.org/) | Biểu đồ trực quan trên web |
| [Rich](https://github.com/Textualize/rich) | CLI dashboard đẹp mắt |

## 🧪 Kiểm thử tấn công DDoS (Lab)

> ⚠️ Chỉ thực hiện trong môi trường lab! Không tấn công hệ thống thật!

### Mô hình lab gợi ý (VMware)
- **Máy tấn công**: Kali Linux
- **Máy nạn nhân**: Metasploitable / Ubuntu Server
- **Mạng**: VMnet (Host-only hoặc NAT)

### Tạo tấn công mẫu bằng hping3 (trên Kali)

```bash
# SYN Flood
sudo hping3 -S --flood -V -p 80 <IP_nạn_nhân>

# UDP Flood
sudo hping3 --udp --flood -p 53 <IP_nạn_nhân>

# ICMP Flood
sudo hping3 --icmp --flood <IP_nạn_nhân>
```

### Quy trình kiểm thử
1. Mở web dashboard: `sudo python3 app.py`
2. Chọn tab **📡 Giám sát Thời gian thực** → Bắt đầu giám sát
3. Mở terminal khác, chạy hping3 tấn công máy nạn nhân
4. Quan sát dashboard: biểu đồ PPS tăng đột biến, cảnh báo DDoS xuất hiện

## 👨‍💻 Tác giả

Đồ án An toàn thông tin - SOC/Blue Team
