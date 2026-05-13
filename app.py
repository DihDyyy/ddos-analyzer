# ============================================================================
# DDoS PCAP Analyzer - Web Application (Flask)
# ============================================================================
# Giao diện web cho công cụ phân tích DDoS từ file .pcap
# Backend: Flask | Frontend: HTML/CSS/JS + Chart.js
# ============================================================================

import os
import sys
import json
import io
import tempfile
import time
from datetime import datetime

# Fix encoding cho Windows
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, render_template, request, jsonify, send_file
import config
from analyzer.packet_parser import PcapParser
from analyzer.statistics import TrafficStatistics
from analyzer.detector import DDoSDetector
from analyzer.reporter import ReportGenerator

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024  # 500MB max upload

# Thư mục lưu file upload và report
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

# Lưu trữ kết quả phân tích gần nhất (in-memory)
latest_result = {}


@app.route("/")
def index():
    """Trang chính."""
    return render_template("index.html", version=config.TOOL_VERSION)


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """
    API phân tích file pcap.
    Nhận file upload, chạy toàn bộ pipeline phân tích, trả về kết quả JSON.
    """
    global latest_result

    # Kiểm tra file upload
    if "pcap_file" not in request.files:
        return jsonify({"error": "Không tìm thấy file. Vui lòng chọn file .pcap/.pcapng"}), 400

    file = request.files["pcap_file"]
    if file.filename == "":
        return jsonify({"error": "Chưa chọn file"}), 400

    # Kiểm tra extension
    allowed_ext = {".pcap", ".pcapng", ".cap"}
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in allowed_ext:
        return jsonify({"error": f"Định dạng file không hợp lệ: {ext}. Chỉ hỗ trợ: .pcap, .pcapng, .cap"}), 400

    # Lấy thresholds từ form
    try:
        syn_threshold = int(request.form.get("syn_threshold", config.SYN_FLOOD_THRESHOLD))
        udp_threshold = int(request.form.get("udp_threshold", config.UDP_FLOOD_THRESHOLD))
        icmp_threshold = int(request.form.get("icmp_threshold", config.ICMP_FLOOD_THRESHOLD))
        http_threshold = int(request.form.get("http_threshold", config.HTTP_FLOOD_THRESHOLD))
    except (ValueError, TypeError):
        return jsonify({"error": "Giá trị ngưỡng không hợp lệ"}), 400

    # Lưu file tạm
    filepath = os.path.join(UPLOAD_DIR, f"upload_{int(time.time())}_{file.filename}")
    file.save(filepath)

    try:
        # ── BƯỚC 1: Parse pcap ──
        parser = PcapParser()
        parsed_packets = parser.load_pcap(filepath)
        parser_summary = parser.get_summary()

        if not parsed_packets:
            return jsonify({"error": "Không tìm thấy packet IP nào trong file"}), 400

        # ── BƯỚC 2: Thống kê ──
        statistics = TrafficStatistics(parsed_packets, time_window=config.TIME_WINDOW)

        # ── BƯỚC 3: Phát hiện DDoS ──
        thresholds = {
            "SYN_FLOOD": syn_threshold,
            "UDP_FLOOD": udp_threshold,
            "ICMP_FLOOD": icmp_threshold,
            "HTTP_FLOOD": http_threshold,
        }
        detector = DDoSDetector(statistics, thresholds=thresholds)
        alerts = detector.run_all_detections()

        # ── BƯỚC 4: Sinh report ──
        reporter = ReportGenerator(parser_summary, statistics, detector)
        report_files = reporter.generate_all(REPORT_DIR)

        # ── Xây dựng kết quả ──
        full_stats = statistics.get_full_statistics()
        capture_info = full_stats.get("capture_info", {})
        protocol_dist = full_stats.get("protocol_distribution", {})
        packet_rate = full_stats.get("packet_rate", {})
        top_ips = full_stats.get("top_source_ips", [])
        top_ports = full_stats.get("top_dst_ports", [])
        http_stats = full_stats.get("http_stats", {})

        result = {
            "success": True,
            "filename": file.filename,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "parser_summary": {
                "file_size_formatted": parser_summary.get("file_size_formatted", "N/A"),
                "total_raw_packets": parser_summary.get("total_raw_packets", 0),
                "total_parsed_packets": parser_summary.get("total_parsed_packets", 0),
                "load_time_seconds": round(parser_summary.get("load_time_seconds", 0), 2),
                "capture_duration": round(parser_summary.get("capture_duration", 0), 2),
            },
            "capture_info": capture_info,
            "protocol_distribution": protocol_dist,
            "packet_rate": {
                "avg_pps": packet_rate.get("avg_pps", 0),
                "max_pps": packet_rate.get("max_pps", 0),
                "min_pps": packet_rate.get("min_pps", 0),
                "timeline": packet_rate.get("timeline", []),
            },
            "top_source_ips": top_ips,
            "top_dst_ports": top_ports,
            "http_stats": http_stats,
            "thresholds": thresholds,
            "risk_level": detector.get_overall_risk_level(),
            "total_alerts": len(alerts),
            "alerts": detector.get_alerts_as_dicts(),
            "attack_summary": _serialize_summary(detector.get_alert_summary()),
            "report_files": {
                "json": os.path.basename(report_files.get("json", "")),
                "csv": [os.path.basename(f) for f in report_files.get("csv", [])],
            },
        }

        latest_result = result
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": f"Lỗi phân tích: {str(e)}"}), 500

    finally:
        # Xóa file upload tạm
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
        except Exception:
            pass


@app.route("/api/download/<filename>")
def download_report(filename):
    """API tải file report."""
    filepath = os.path.join(REPORT_DIR, filename)
    if not os.path.exists(filepath):
        return jsonify({"error": "File không tồn tại"}), 404
    return send_file(filepath, as_attachment=True)


def _serialize_summary(summary):
    """Chuyển đổi attack summary cho JSON serialization."""
    result = {}
    for k, v in summary.items():
        item = dict(v)
        if "source_ips" in item and isinstance(item["source_ips"], (set, list)):
            item["source_ips"] = list(item["source_ips"])
        result[k] = item
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("  DDoS PCAP Analyzer - Web UI")
    print(f"  Version {config.TOOL_VERSION}")
    print("  Mở trình duyệt tại: http://localhost:5000")
    print("=" * 60)
    app.run(debug=True, host="0.0.0.0", port=5000)
