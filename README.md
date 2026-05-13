# 🛡️ DDoS PCAP Analyzer

> Công cụ phân tích file `.pcap` từ Wireshark để phát hiện dấu hiệu tấn công DDoS tầng 3, 4, và 7.
> Thiết kế theo hướng SOC/Blue Team phục vụ đồ án An toàn thông tin.

## 🎯 Tính năng

| Tính năng | Chi tiết |
|---|---|
| **Phân tích giao thức** | TCP, UDP, ICMP, HTTP (Layer 3/4/7) |
| **Phát hiện tấn công** | SYN Flood, UDP Flood, ICMP Flood, HTTP Request Flood |
| **Thống kê IP** | Top source IPs với phân bố giao thức và đánh giá rủi ro |
| **Tốc độ Packet** | Hiển thị PPS (packets/second) với sparkline timeline |
| **Cảnh báo Real-time** | Alerts trên terminal với severity: CRITICAL/HIGH/MEDIUM/LOW |
| **Báo cáo** | Xuất JSON và CSV (alerts, top IPs, statistics) |
| **Dashboard CLI** | Giao diện terminal trực quan với Rich (màu sắc, bảng, biểu đồ) |

## 📋 Yêu cầu hệ thống

- **Python** >= 3.8
- **Windows** (đã test) / Linux / macOS
- **Npcap** (thường đi kèm khi cài Wireshark) - [Tải tại đây](https://npcap.com/)

## 🚀 Cài đặt

```bash
# 1. Clone/tải về thư mục dự án
cd ddos-analyzer

# 2. Cài đặt thư viện cần thiết
pip install -r requirements.txt

# 3. Kiểm tra cài đặt
python main.py --help
```

## 📖 Cách sử dụng

### Cơ bản
```bash
# Phân tích file pcap
python main.py capture.pcap
```

### Tùy chỉnh ngưỡng phát hiện
```bash
# Giảm ngưỡng SYN Flood xuống 50 packets/giây
python main.py capture.pcap --syn-threshold 50

# Tùy chỉnh tất cả ngưỡng
python main.py capture.pcap --syn-threshold 50 --udp-threshold 100 --icmp-threshold 30 --http-threshold 25
```

### Tùy chỉnh đầu ra
```bash
# Chỉ xuất JSON report
python main.py capture.pcap --format json

# Chỉ xuất CSV
python main.py capture.pcap --format csv

# Chỉ định thư mục output
python main.py capture.pcap --output-dir ./my_reports

# Chỉ hiển thị dashboard, không xuất report
python main.py capture.pcap --no-report

# Chỉ xuất report, không hiển thị dashboard
python main.py capture.pcap --no-dashboard
```

### Hiển thị nhiều Top IPs
```bash
python main.py capture.pcap --top 20
```

## ⚙️ Cấu hình ngưỡng phát hiện

Các ngưỡng mặc định trong `config.py`:

| Tấn công | Ngưỡng mặc định | Ý nghĩa |
|---|---|---|
| SYN Flood | 100 pkt/s | TCP SYN packets/giây từ 1 IP |
| UDP Flood | 200 pkt/s | UDP packets/giây từ 1 IP |
| ICMP Flood | 50 pkt/s | ICMP packets/giây từ 1 IP |
| HTTP Flood | 50 req/s | HTTP requests/giây từ 1 IP |

### Mức độ cảnh báo (Severity)

| Mức độ | Tỷ lệ so với ngưỡng |
|---|---|
| 🔵 LOW | >= 1x |
| 🟡 MEDIUM | >= 2x |
| 🟠 HIGH | >= 5x |
| 🔴 CRITICAL | >= 10x |

## 📁 Cấu trúc dự án

```
ddos-analyzer/
├── main.py                  # Entry point - CLI interface
├── config.py                # Cấu hình ngưỡng phát hiện
├── requirements.txt         # Thư viện cần thiết
├── README.md                # Hướng dẫn sử dụng
├── analyzer/                # Package phân tích
│   ├── __init__.py
│   ├── packet_parser.py     # Đọc & parse pcap (Scapy)
│   ├── statistics.py        # Thống kê traffic
│   ├── detector.py          # Engine phát hiện DDoS
│   ├── dashboard.py         # CLI Dashboard (Rich)
│   └── reporter.py          # Xuất báo cáo JSON/CSV
└── reports/                 # Thư mục chứa report (tự tạo)
    ├── ddos_report_*.json
    ├── ddos_alerts_*.csv
    ├── ddos_top_ips_*.csv
    └── ddos_statistics_*.csv
```

## 🔍 Giải thích phương pháp phát hiện

### SYN Flood (Layer 4)
- **Nguyên lý**: Đếm số TCP SYN packets (không có ACK flag) từ mỗi source IP trong mỗi giây
- **Dấu hiệu**: Lượng SYN packets/giây từ 1 IP vượt ngưỡng bất thường
- **Mục đích tấn công**: Làm cạn kiệt bảng kết nối (connection table) của server

### UDP Flood (Layer 4)
- **Nguyên lý**: Đếm số UDP packets từ mỗi source IP trong mỗi giây
- **Dấu hiệu**: Lượng UDP packets/giây từ 1 IP vượt ngưỡng bất thường
- **Mục đích tấn công**: Gây nghẽn bandwidth với traffic UDP connectionless

### ICMP Flood (Layer 3)
- **Nguyên lý**: Đếm số ICMP packets (ping) từ mỗi source IP trong mỗi giây
- **Dấu hiệu**: Lượng ICMP packets/giây từ 1 IP vượt ngưỡng bất thường
- **Mục đích tấn công**: Gây nghẽn bandwidth bằng ICMP Echo Request

### HTTP Flood (Layer 7)
- **Nguyên lý**: Đếm số HTTP requests (GET, POST, ...) từ mỗi source IP trong mỗi giây
- **Dấu hiệu**: Lượng HTTP requests/giây từ 1 IP vượt ngưỡng bất thường
- **Mục đích tấn công**: Quá tải web server với requests hợp lệ (khó lọc)

## 📊 Báo cáo đầu ra

### JSON Report
File `ddos_report_<timestamp>.json` chứa:
- Metadata (thời gian phân tích, file name, tool version)
- Thống kê capture (tổng packets, duration, unique IPs, ...)
- Phân bố giao thức (TCP/UDP/ICMP/HTTP)
- Packet rate (avg, max, min PPS)
- Top source IPs
- Kết quả phát hiện & danh sách alerts
- Đánh giá rủi ro tổng thể

### CSV Reports
- `ddos_alerts_<timestamp>.csv` - Danh sách tất cả cảnh báo
- `ddos_top_ips_<timestamp>.csv` - Top source IPs
- `ddos_statistics_<timestamp>.csv` - Thống kê tổng quan

## 🛠️ Công nghệ sử dụng

| Thư viện | Mục đích |
|---|---|
| [Scapy](https://scapy.net/) | Đọc file pcap, phân tích packet ở mức low-level |
| [Rich](https://github.com/Textualize/rich) | CLI dashboard đẹp mắt với bảng, màu sắc, progress bar |

## 📝 Tạo file pcap mẫu

### Cách 1: Dùng Wireshark
1. Mở Wireshark -> Capture -> Start
2. Thực hiện các hoạt động mạng
3. File -> Save As -> Chọn định dạng `.pcap`

### Cách 2: Dùng tcpdump (Linux)
```bash
sudo tcpdump -i eth0 -w capture.pcap -c 10000
```

### Cách 3: Tải pcap mẫu
- [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures)

## 👨‍💻 Tác giả

Đồ án An toàn thông tin - SOC/Blue Team
