# ============================================================================
# DDoS PCAP Analyzer - Report Generator Module
# ============================================================================
# Xuất báo cáo phân tích dưới dạng JSON và CSV
# Hỗ trợ lưu trữ kết quả để phục vụ điều tra, báo cáo SOC
# ============================================================================

import json
import csv
import os
from datetime import datetime

from rich.console import Console

import config

console = Console()


class ReportGenerator:
    """
    Module xuất báo cáo phân tích DDoS.
    Hỗ trợ định dạng JSON và CSV.
    """

    def __init__(self, parser_summary, statistics, detector):
        """
        Args:
            parser_summary (dict): Thông tin file pcap
            statistics (TrafficStatistics): Object thống kê
            detector (DDoSDetector): Object phát hiện
        """
        self.parser_summary = parser_summary
        self.statistics = statistics
        self.detector = detector
        self.report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def _build_report_data(self):
        """
        Xây dựng dữ liệu báo cáo đầy đủ.

        Returns:
            dict: Dữ liệu báo cáo
        """
        full_stats = self.statistics.get_full_statistics()

        return {
            "metadata": {
                "tool_name": config.TOOL_NAME,
                "tool_version": config.TOOL_VERSION,
                "report_generated_at": self.report_time,
                "analyzed_file": self.parser_summary.get("file_path", "N/A"),
                "file_size": self.parser_summary.get("file_size_formatted", "N/A"),
            },
            "capture_info": full_stats.get("capture_info", {}),
            "protocol_distribution": full_stats.get("protocol_distribution", {}),
            "packet_rate": {
                "avg_pps": full_stats.get("packet_rate", {}).get("avg_pps", 0),
                "max_pps": full_stats.get("packet_rate", {}).get("max_pps", 0),
                "min_pps": full_stats.get("packet_rate", {}).get("min_pps", 0),
            },
            "top_source_ips": full_stats.get("top_source_ips", []),
            "top_destination_ports": full_stats.get("top_dst_ports", []),
            "http_statistics": full_stats.get("http_stats", {}),
            "detection_thresholds": {
                "syn_flood": config.SYN_FLOOD_THRESHOLD,
                "udp_flood": config.UDP_FLOOD_THRESHOLD,
                "icmp_flood": config.ICMP_FLOOD_THRESHOLD,
                "http_flood": config.HTTP_FLOOD_THRESHOLD,
            },
            "overall_risk_level": self.detector.get_overall_risk_level(),
            "attack_summary": self.detector.get_alert_summary(),
            "alerts": self.detector.get_alerts_as_dicts(),
            "total_alerts": len(self.detector.alerts),
        }

    def generate_json(self, output_dir="reports"):
        """
        Xuất báo cáo dưới dạng JSON.

        Args:
            output_dir (str): Thư mục đầu ra

        Returns:
            str: Đường dẫn file báo cáo
        """
        os.makedirs(output_dir, exist_ok=True)

        report_data = self._build_report_data()

        # Chuyển set thành list cho JSON serialization
        report_data = self._make_json_serializable(report_data)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"ddos_report_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        console.print(f"  [green]✅ JSON Report:[/] {os.path.abspath(filepath)}")
        return filepath

    def generate_csv(self, output_dir="reports"):
        """
        Xuất báo cáo dưới dạng CSV (nhiều file).

        Args:
            output_dir (str): Thư mục đầu ra

        Returns:
            list[str]: Danh sách đường dẫn file CSV
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        generated_files = []

        # 1. Alerts CSV
        alerts_file = os.path.join(output_dir, f"ddos_alerts_{timestamp}.csv")
        alerts_data = self.detector.get_alerts_as_dicts()

        if alerts_data:
            with open(alerts_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=alerts_data[0].keys())
                writer.writeheader()
                writer.writerows(alerts_data)
            generated_files.append(alerts_file)
            console.print(f"  [green]✅ Alerts CSV:[/] {os.path.abspath(alerts_file)}")
        else:
            # Tạo file CSV trống với header
            with open(alerts_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["attack_type", "source_ip", "time_slot_second",
                                 "packet_count", "threshold", "ratio", "severity",
                                 "detection_time"])
            generated_files.append(alerts_file)
            console.print(f"  [green]✅ Alerts CSV (trống):[/] {os.path.abspath(alerts_file)}")

        # 2. Top Source IPs CSV
        ips_file = os.path.join(output_dir, f"ddos_top_ips_{timestamp}.csv")
        top_ips = self.statistics.get_top_source_ips(config.TOP_TALKERS_COUNT)

        with open(ips_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["rank", "source_ip", "packet_count", "percentage", "protocols"])
            for i, ip_data in enumerate(top_ips, 1):
                proto_str = "; ".join(
                    f"{k}:{v}" for k, v in ip_data["protocols"].items()
                )
                writer.writerow([
                    i, ip_data["ip"], ip_data["count"],
                    f"{ip_data['percentage']}%", proto_str
                ])
        generated_files.append(ips_file)
        console.print(f"  [green]✅ Top IPs CSV:[/] {os.path.abspath(ips_file)}")

        # 3. Statistics Summary CSV
        stats_file = os.path.join(output_dir, f"ddos_statistics_{timestamp}.csv")
        capture_info = self.statistics.get_capture_info()
        packet_rate = self.statistics.get_packet_rate()

        with open(stats_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["metric", "value"])

            writer.writerow(["tool_name", config.TOOL_NAME])
            writer.writerow(["tool_version", config.TOOL_VERSION])
            writer.writerow(["report_time", self.report_time])
            writer.writerow(["analyzed_file", self.parser_summary.get("file_path", "")])
            writer.writerow(["total_packets", capture_info.get("total_packets", 0)])
            writer.writerow(["total_bytes", capture_info.get("total_bytes", 0)])
            writer.writerow(["capture_duration_s", capture_info.get("capture_duration_seconds", 0)])
            writer.writerow(["unique_src_ips", capture_info.get("unique_src_ips", 0)])
            writer.writerow(["unique_dst_ips", capture_info.get("unique_dst_ips", 0)])
            writer.writerow(["avg_pps", packet_rate.get("avg_pps", 0)])
            writer.writerow(["max_pps", packet_rate.get("max_pps", 0)])
            writer.writerow(["overall_risk_level", self.detector.get_overall_risk_level()])
            writer.writerow(["total_alerts", len(self.detector.alerts)])

            # Protocol distribution
            for proto, data in self.statistics.get_protocol_distribution().items():
                writer.writerow([f"protocol_{proto}_count", data["count"]])
                writer.writerow([f"protocol_{proto}_pct", f"{data['percentage']}%"])

            # Attack summary
            for attack, data in self.detector.get_alert_summary().items():
                writer.writerow([f"attack_{attack}_alerts", data["total_alerts"]])
                writer.writerow([f"attack_{attack}_ips", data["unique_source_ips"]])
                writer.writerow([f"attack_{attack}_max_pps", data["max_packets_per_second"]])
                writer.writerow([f"attack_{attack}_severity", data["max_severity"]])

        generated_files.append(stats_file)
        console.print(f"  [green]✅ Statistics CSV:[/] {os.path.abspath(stats_file)}")

        return generated_files

    def generate_all(self, output_dir="reports"):
        """
        Xuất cả JSON và CSV.

        Args:
            output_dir (str): Thư mục đầu ra

        Returns:
            dict: Đường dẫn các file đã tạo
        """
        console.print()
        console.print("[bold cyan]📄 Đang xuất báo cáo...[/]")
        console.print()

        json_file = self.generate_json(output_dir)
        csv_files = self.generate_csv(output_dir)

        console.print()
        console.print(f"[bold green]✅ Đã xuất {1 + len(csv_files)} file báo cáo vào:[/] {os.path.abspath(output_dir)}")

        return {
            "json": json_file,
            "csv": csv_files,
        }

    def _make_json_serializable(self, obj):
        """Chuyển đổi các object không serializable (set, ...) thành JSON-friendly."""
        if isinstance(obj, dict):
            return {k: self._make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._make_json_serializable(item) for item in obj]
        elif isinstance(obj, set):
            return list(obj)
        elif isinstance(obj, (int, float, str, bool, type(None))):
            return obj
        else:
            return str(obj)
