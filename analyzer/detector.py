# ============================================================================
# DDoS PCAP Analyzer - DDoS Detection Engine
# ============================================================================
# Phát hiện các loại tấn công DDoS: SYN Flood, UDP Flood,
# ICMP Flood, HTTP Request Flood
# Dựa trên phân tích ngưỡng (threshold-based detection)
# ============================================================================

from datetime import datetime
from collections import defaultdict

import config


class Alert:
    """
    Đối tượng cảnh báo DDoS.
    Chứa thông tin chi tiết về một phát hiện tấn công.
    """

    def __init__(self, attack_type, source_ip, time_slot, packet_count, threshold, severity):
        self.attack_type = attack_type      # str: SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, HTTP_FLOOD
        self.source_ip = source_ip          # str: IP nguồn tấn công
        self.time_slot = time_slot          # int: slot thời gian phát hiện
        self.packet_count = packet_count    # int: số packets trong time window
        self.threshold = threshold          # int: ngưỡng đã vượt
        self.severity = severity            # str: LOW, MEDIUM, HIGH, CRITICAL
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.ratio = round(packet_count / threshold, 2) if threshold > 0 else 0

    def to_dict(self):
        """Chuyển đổi thành dict để xuất báo cáo."""
        return {
            "attack_type": self.attack_type,
            "source_ip": self.source_ip,
            "time_slot_second": self.time_slot,
            "packet_count": self.packet_count,
            "threshold": self.threshold,
            "ratio": self.ratio,
            "severity": self.severity,
            "detection_time": self.timestamp,
        }

    def __repr__(self):
        return (f"Alert({self.severity} {self.attack_type} from {self.source_ip} "
                f"| {self.packet_count} pkts [{self.ratio}x threshold])")


class DDoSDetector:
    """
    Engine phát hiện DDoS sử dụng phương pháp threshold-based detection.
    Phân tích traffic theo từng time window để phát hiện bất thường.
    """

    # Tên hiển thị cho từng loại tấn công
    ATTACK_NAMES = {
        "SYN_FLOOD": "🔴 SYN Flood (Layer 4)",
        "UDP_FLOOD": "🟠 UDP Flood (Layer 4)",
        "ICMP_FLOOD": "🟡 ICMP Flood (Layer 3)",
        "HTTP_FLOOD": "🟣 HTTP Flood (Layer 7)",
    }

    # Mô tả từng loại tấn công
    ATTACK_DESCRIPTIONS = {
        "SYN_FLOOD": "Gửi lượng lớn TCP SYN packets để làm cạn kiệt tài nguyên server",
        "UDP_FLOOD": "Gửi lượng lớn UDP packets đến các port ngẫu nhiên trên target",
        "ICMP_FLOOD": "Gửi lượng lớn ICMP Echo Request (ping) để gây nghẽn bandwidth",
        "HTTP_FLOOD": "Gửi lượng lớn HTTP requests hợp lệ để quá tải web server",
    }

    def __init__(self, statistics, thresholds=None):
        """
        Args:
            statistics (TrafficStatistics): Object thống kê traffic
            thresholds (dict, optional): Ngưỡng tùy chỉnh
        """
        self.stats = statistics
        self.alerts = []
        self.attack_summary = defaultdict(lambda: {
            "total_alerts": 0,
            "unique_ips": set(),
            "max_pps": 0,
            "max_severity": "LOW",
        })

        # Ngưỡng phát hiện - có thể tùy chỉnh
        self.thresholds = thresholds or {
            "SYN_FLOOD": config.SYN_FLOOD_THRESHOLD,
            "UDP_FLOOD": config.UDP_FLOOD_THRESHOLD,
            "ICMP_FLOOD": config.ICMP_FLOOD_THRESHOLD,
            "HTTP_FLOOD": config.HTTP_FLOOD_THRESHOLD,
        }

    def _determine_severity(self, packet_count, threshold):
        """
        Xác định mức độ nghiêm trọng dựa trên tỷ lệ vượt ngưỡng.

        Args:
            packet_count (int): Số packets thực tế
            threshold (int): Ngưỡng cấu hình

        Returns:
            str: Mức độ (CRITICAL/HIGH/MEDIUM/LOW)
        """
        ratio = packet_count / threshold if threshold > 0 else 0
        severity_levels = config.SEVERITY_LEVELS

        if ratio >= severity_levels["CRITICAL"]:
            return "CRITICAL"
        elif ratio >= severity_levels["HIGH"]:
            return "HIGH"
        elif ratio >= severity_levels["MEDIUM"]:
            return "MEDIUM"
        else:
            return "LOW"

    def _severity_rank(self, severity):
        """Chuyển severity thành số để so sánh."""
        ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return ranks.get(severity, 0)

    def detect_syn_flood(self):
        """
        Phát hiện SYN Flood Attack (Layer 4).

        Nguyên lý: Đếm số TCP SYN packets (không có ACK) từ mỗi source IP
        trong mỗi time window. Nếu vượt ngưỡng -> cảnh báo.
        """
        threshold = self.thresholds["SYN_FLOOD"]
        syn_alerts = []

        for time_slot, ip_counts in self.stats.syn_timeline.items():
            for ip, count in ip_counts.items():
                if count >= threshold:
                    severity = self._determine_severity(count, threshold)
                    alert = Alert(
                        attack_type="SYN_FLOOD",
                        source_ip=ip,
                        time_slot=time_slot,
                        packet_count=count,
                        threshold=threshold,
                        severity=severity,
                    )
                    syn_alerts.append(alert)
                    self._update_summary("SYN_FLOOD", alert)

        self.alerts.extend(syn_alerts)
        return syn_alerts

    def detect_udp_flood(self):
        """
        Phát hiện UDP Flood Attack (Layer 4).

        Nguyên lý: Đếm số UDP packets từ mỗi source IP
        trong mỗi time window. Nếu vượt ngưỡng -> cảnh báo.
        """
        threshold = self.thresholds["UDP_FLOOD"]
        udp_alerts = []

        for time_slot, ip_counts in self.stats.udp_timeline.items():
            for ip, count in ip_counts.items():
                if count >= threshold:
                    severity = self._determine_severity(count, threshold)
                    alert = Alert(
                        attack_type="UDP_FLOOD",
                        source_ip=ip,
                        time_slot=time_slot,
                        packet_count=count,
                        threshold=threshold,
                        severity=severity,
                    )
                    udp_alerts.append(alert)
                    self._update_summary("UDP_FLOOD", alert)

        self.alerts.extend(udp_alerts)
        return udp_alerts

    def detect_icmp_flood(self):
        """
        Phát hiện ICMP Flood Attack (Layer 3).

        Nguyên lý: Đếm số ICMP packets từ mỗi source IP
        trong mỗi time window. Nếu vượt ngưỡng -> cảnh báo.
        """
        threshold = self.thresholds["ICMP_FLOOD"]
        icmp_alerts = []

        for time_slot, ip_counts in self.stats.icmp_timeline.items():
            for ip, count in ip_counts.items():
                if count >= threshold:
                    severity = self._determine_severity(count, threshold)
                    alert = Alert(
                        attack_type="ICMP_FLOOD",
                        source_ip=ip,
                        time_slot=time_slot,
                        packet_count=count,
                        threshold=threshold,
                        severity=severity,
                    )
                    icmp_alerts.append(alert)
                    self._update_summary("ICMP_FLOOD", alert)

        self.alerts.extend(icmp_alerts)
        return icmp_alerts

    def detect_http_flood(self):
        """
        Phát hiện HTTP Flood Attack (Layer 7).

        Nguyên lý: Đếm số HTTP requests (GET, POST, ...) từ mỗi source IP
        trong mỗi time window. Nếu vượt ngưỡng -> cảnh báo.
        """
        threshold = self.thresholds["HTTP_FLOOD"]
        http_alerts = []

        for time_slot, ip_counts in self.stats.http_timeline.items():
            for ip, count in ip_counts.items():
                if count >= threshold:
                    severity = self._determine_severity(count, threshold)
                    alert = Alert(
                        attack_type="HTTP_FLOOD",
                        source_ip=ip,
                        time_slot=time_slot,
                        packet_count=count,
                        threshold=threshold,
                        severity=severity,
                    )
                    http_alerts.append(alert)
                    self._update_summary("HTTP_FLOOD", alert)

        self.alerts.extend(http_alerts)
        return http_alerts

    def _update_summary(self, attack_type, alert):
        """Cập nhật tổng kết cho từng loại tấn công."""
        summary = self.attack_summary[attack_type]
        summary["total_alerts"] += 1
        summary["unique_ips"].add(alert.source_ip)
        summary["max_pps"] = max(summary["max_pps"], alert.packet_count)
        if self._severity_rank(alert.severity) > self._severity_rank(summary["max_severity"]):
            summary["max_severity"] = alert.severity

    def run_all_detections(self):
        """
        Chạy tất cả các phương pháp phát hiện.

        Returns:
            list[Alert]: Danh sách tất cả cảnh báo
        """
        self.alerts = []
        self.attack_summary = defaultdict(lambda: {
            "total_alerts": 0,
            "unique_ips": set(),
            "max_pps": 0,
            "max_severity": "LOW",
        })

        self.detect_syn_flood()
        self.detect_udp_flood()
        self.detect_icmp_flood()
        self.detect_http_flood()

        # Sắp xếp alerts theo severity (CRITICAL trước)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.alerts.sort(key=lambda a: (severity_order.get(a.severity, 4), a.time_slot))

        return self.alerts

    def get_alert_summary(self):
        """
        Trả về bản tổng kết các tấn công phát hiện được.

        Returns:
            dict: Tổng kết theo từng loại tấn công
        """
        result = {}
        for attack_type, summary in self.attack_summary.items():
            result[attack_type] = {
                "display_name": self.ATTACK_NAMES.get(attack_type, attack_type),
                "description": self.ATTACK_DESCRIPTIONS.get(attack_type, ""),
                "total_alerts": summary["total_alerts"],
                "unique_source_ips": len(summary["unique_ips"]),
                "source_ips": list(summary["unique_ips"]),
                "max_packets_per_second": summary["max_pps"],
                "max_severity": summary["max_severity"],
                "threshold_used": self.thresholds.get(attack_type, 0),
            }
        return result

    def get_overall_risk_level(self):
        """
        Đánh giá mức độ rủi ro tổng thể.

        Returns:
            str: CRITICAL/HIGH/MEDIUM/LOW/SAFE
        """
        if not self.alerts:
            return "SAFE"

        severities = [a.severity for a in self.alerts]
        if "CRITICAL" in severities:
            return "CRITICAL"
        elif "HIGH" in severities:
            return "HIGH"
        elif "MEDIUM" in severities:
            return "MEDIUM"
        else:
            return "LOW"

    def get_alerts_as_dicts(self):
        """Trả về danh sách alerts dưới dạng dict."""
        return [alert.to_dict() for alert in self.alerts]
