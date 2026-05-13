# ============================================================================
# DDoS PCAP Analyzer - Traffic Statistics Module
# ============================================================================
# Thu thập và tính toán thống kê traffic từ packets đã parse
# Cung cấp dữ liệu cho Dashboard và Report
# ============================================================================

from collections import defaultdict, Counter
from datetime import datetime


class TrafficStatistics:
    """
    Module thu thập và tính toán các thống kê traffic.
    Phân tích phân bố giao thức, top source IPs, packet rate, v.v.
    """

    def __init__(self, parsed_packets, time_window=1.0):
        """
        Args:
            parsed_packets (list[ParsedPacket]): Danh sách packets đã parse
            time_window (float): Cửa sổ thời gian để tính PPS (giây)
        """
        self.packets = parsed_packets
        self.time_window = time_window

        # Kết quả thống kê
        self.protocol_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.dst_port_counts = Counter()
        self.src_ip_protocol = defaultdict(lambda: Counter())
        self.packet_sizes = []
        self.timeline = defaultdict(int)  # second -> packet count
        self.syn_timeline = defaultdict(lambda: Counter())  # second -> {ip: count}
        self.udp_timeline = defaultdict(lambda: Counter())
        self.icmp_timeline = defaultdict(lambda: Counter())
        self.http_timeline = defaultdict(lambda: Counter())
        self.http_methods = Counter()
        self.http_uris = Counter()

        # Tính toán
        self._compute_statistics()

    def _compute_statistics(self):
        """Tính toán tất cả các thống kê từ danh sách packets."""
        if not self.packets:
            return

        base_time = self.packets[0].timestamp

        for pkt in self.packets:
            # Thống kê cơ bản
            self.protocol_counts[pkt.protocol] += 1
            self.src_ip_counts[pkt.src_ip] += 1
            self.dst_ip_counts[pkt.dst_ip] += 1
            self.packet_sizes.append(pkt.packet_size)
            self.src_ip_protocol[pkt.src_ip][pkt.protocol] += 1

            if pkt.dst_port:
                self.dst_port_counts[pkt.dst_port] += 1

            # Timeline: nhóm packets theo giây
            time_slot = int((pkt.timestamp - base_time) / self.time_window)
            self.timeline[time_slot] += 1

            # Timeline theo loại tấn công
            if pkt.is_syn:
                self.syn_timeline[time_slot][pkt.src_ip] += 1

            if pkt.protocol == "UDP":
                self.udp_timeline[time_slot][pkt.src_ip] += 1

            if pkt.protocol == "ICMP":
                self.icmp_timeline[time_slot][pkt.src_ip] += 1

            if pkt.is_http and pkt.http_method and pkt.http_method != "RESPONSE":
                self.http_timeline[time_slot][pkt.src_ip] += 1
                self.http_methods[pkt.http_method] += 1
                if pkt.http_uri:
                    self.http_uris[pkt.http_uri] += 1

    def get_protocol_distribution(self):
        """
        Phân bố giao thức.

        Returns:
            dict: {protocol: {"count": int, "percentage": float}}
        """
        total = sum(self.protocol_counts.values())
        if total == 0:
            return {}

        result = {}
        for proto, count in self.protocol_counts.most_common():
            result[proto] = {
                "count": count,
                "percentage": round((count / total) * 100, 2),
            }
        return result

    def get_top_source_ips(self, top_n=10):
        """
        Top N source IPs theo số lượng packets.

        Args:
            top_n (int): Số lượng IP cần trả về

        Returns:
            list[dict]: Danh sách {"ip", "count", "percentage", "protocols"}
        """
        total = sum(self.src_ip_counts.values())
        if total == 0:
            return []

        result = []
        for ip, count in self.src_ip_counts.most_common(top_n):
            protocols = dict(self.src_ip_protocol[ip])
            result.append({
                "ip": ip,
                "count": count,
                "percentage": round((count / total) * 100, 2),
                "protocols": protocols,
            })
        return result

    def get_top_dst_ports(self, top_n=10):
        """
        Top N destination ports.

        Returns:
            list[dict]: Danh sách {"port", "count", "percentage"}
        """
        total = sum(self.dst_port_counts.values())
        if total == 0:
            return []

        result = []
        for port, count in self.dst_port_counts.most_common(top_n):
            result.append({
                "port": port,
                "count": count,
                "percentage": round((count / total) * 100, 2),
            })
        return result

    def get_packet_rate(self):
        """
        Tính toán packet rate (PPS).

        Returns:
            dict: {"avg_pps", "max_pps", "min_pps", "timeline"}
        """
        if not self.timeline:
            return {"avg_pps": 0, "max_pps": 0, "min_pps": 0, "timeline": []}

        values = list(self.timeline.values())
        timeline_data = []
        max_slot = max(self.timeline.keys()) if self.timeline else 0

        for i in range(max_slot + 1):
            timeline_data.append(self.timeline.get(i, 0))

        return {
            "avg_pps": round(sum(values) / len(values), 2) if values else 0,
            "max_pps": max(values) if values else 0,
            "min_pps": min(values) if values else 0,
            "timeline": timeline_data,
        }

    def get_capture_info(self):
        """
        Thông tin tổng quan về capture.

        Returns:
            dict: Thông tin tổng quan
        """
        if not self.packets:
            return {}

        duration = self.packets[-1].timestamp - self.packets[0].timestamp
        total_bytes = sum(self.packet_sizes)

        return {
            "total_packets": len(self.packets),
            "capture_duration_seconds": round(duration, 2),
            "total_bytes": total_bytes,
            "total_bytes_formatted": self._format_size(total_bytes),
            "avg_packet_size": round(total_bytes / len(self.packets), 2) if self.packets else 0,
            "unique_src_ips": len(self.src_ip_counts),
            "unique_dst_ips": len(self.dst_ip_counts),
            "unique_dst_ports": len(self.dst_port_counts),
            "start_time": datetime.fromtimestamp(self.packets[0].timestamp).strftime("%Y-%m-%d %H:%M:%S"),
            "end_time": datetime.fromtimestamp(self.packets[-1].timestamp).strftime("%Y-%m-%d %H:%M:%S"),
        }

    def get_http_stats(self):
        """
        Thống kê HTTP traffic.

        Returns:
            dict: {"methods": Counter, "top_uris": list}
        """
        return {
            "methods": dict(self.http_methods),
            "top_uris": [
                {"uri": uri, "count": count}
                for uri, count in self.http_uris.most_common(10)
            ],
            "total_requests": sum(self.http_methods.values()),
        }

    def get_full_statistics(self):
        """
        Trả về toàn bộ thống kê dưới dạng dict.

        Returns:
            dict: Toàn bộ thống kê
        """
        return {
            "capture_info": self.get_capture_info(),
            "protocol_distribution": self.get_protocol_distribution(),
            "top_source_ips": self.get_top_source_ips(),
            "top_dst_ports": self.get_top_dst_ports(),
            "packet_rate": self.get_packet_rate(),
            "http_stats": self.get_http_stats(),
        }

    @staticmethod
    def _format_size(size_bytes):
        """Format kích thước cho dễ đọc."""
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
