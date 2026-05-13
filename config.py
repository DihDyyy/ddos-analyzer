# ============================================================================
# DDoS PCAP Analyzer - Configuration / Cấu hình ngưỡng phát hiện
# ============================================================================
# Công cụ phân tích DDoS cho SOC/Blue Team
# Tùy chỉnh các ngưỡng phát hiện tại đây
# ============================================================================

# ---------------------------------------------------------------------------
# Ngưỡng phát hiện tấn công (packets/giây từ 1 source IP)
# ---------------------------------------------------------------------------

# SYN Flood: Số TCP SYN packets/giây từ 1 IP vượt ngưỡng -> cảnh báo
SYN_FLOOD_THRESHOLD = 100

# UDP Flood: Số UDP packets/giây từ 1 IP vượt ngưỡng -> cảnh báo
UDP_FLOOD_THRESHOLD = 200

# ICMP Flood: Số ICMP packets/giây từ 1 IP vượt ngưỡng -> cảnh báo
ICMP_FLOOD_THRESHOLD = 50

# HTTP Flood (Layer 7): Số HTTP requests/giây từ 1 IP vượt ngưỡng -> cảnh báo
HTTP_FLOOD_THRESHOLD = 50

# ---------------------------------------------------------------------------
# Mức độ cảnh báo (Severity Levels)
# ---------------------------------------------------------------------------
# Tỷ lệ so với ngưỡng để xác định mức độ nghiêm trọng
SEVERITY_LEVELS = {
    "LOW": 1.0,        # >= 1x threshold
    "MEDIUM": 2.0,     # >= 2x threshold
    "HIGH": 5.0,       # >= 5x threshold
    "CRITICAL": 10.0,  # >= 10x threshold
}

# ---------------------------------------------------------------------------
# Hiển thị & Báo cáo
# ---------------------------------------------------------------------------

# Số lượng Top Source IP hiển thị
TOP_TALKERS_COUNT = 10

# Cửa sổ thời gian phân tích (giây)
TIME_WINDOW = 1.0

# Phiên bản công cụ
TOOL_VERSION = "1.0.0"
TOOL_NAME = "DDoS PCAP Analyzer"
TOOL_AUTHOR = "SOC/Blue Team"
