# ============================================================================
# DDoS Analyzer - Live Packet Sniffer Module (tshark backend)
# ============================================================================
# Bắt gói tin thời gian thực sử dụng tshark (Wireshark CLI)
# Chạy tshark subprocess, parse output, phát hiện DDoS real-time
# ============================================================================

import time
import threading
import subprocess
import shutil
from collections import defaultdict, Counter, deque
from datetime import datetime

import config


class LiveSniffer:
    """
    Module bắt gói tin thời gian thực bằng tshark.
    Chạy tshark subprocess và parse output liên tục.
    """

    def __init__(self, interface=None, thresholds=None):
        self.interface = interface
        self.thresholds = thresholds or {
            "SYN_FLOOD": config.SYN_FLOOD_THRESHOLD,
            "UDP_FLOOD": config.UDP_FLOOD_THRESHOLD,
            "ICMP_FLOOD": config.ICMP_FLOOD_THRESHOLD,
            "HTTP_FLOOD": config.HTTP_FLOOD_THRESHOLD,
        }

        # Trạng thái
        self.is_running = False
        self._process = None
        self._thread = None
        self._lock = threading.Lock()

        # Thống kê
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = None
        self.protocol_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_port_counts = Counter()
        self.src_ip_protocol = defaultdict(lambda: Counter())

        # Timeline PPS (giữ 300s)
        self.pps_timeline = deque(maxlen=300)
        self._current_second_count = 0
        self._last_second = 0

        # Per-second tracking cho detection
        self._syn_per_second = defaultdict(lambda: Counter())
        self._udp_per_second = defaultdict(lambda: Counter())
        self._icmp_per_second = defaultdict(lambda: Counter())
        self._http_per_second = defaultdict(lambda: Counter())

        # Alerts (giữ 200 gần nhất)
        self.alerts = deque(maxlen=200)
        self._alert_cooldown = {}

        # Packets gần nhất
        self.recent_packets = deque(maxlen=50)

        # HTTP stats
        self.http_methods = Counter()
        self.total_http_requests = 0

    def get_interfaces(self):
        """Lấy danh sách card mạng từ tshark."""
        try:
            tshark = self._find_tshark()
            if not tshark:
                return []
            r = subprocess.run(
                [tshark, "-D"],
                capture_output=True, text=True, timeout=5
            )
            ifaces = []
            for line in r.stdout.strip().split("\n"):
                if line.strip():
                    # Format: "1. eth0" hoặc "1. eth0 (Description)"
                    parts = line.split(".", 1)
                    if len(parts) >= 2:
                        name = parts[1].strip().split(" ")[0]
                        ifaces.append(name)
            return ifaces
        except Exception as e:
            print(f"[LiveSniffer] Lỗi lấy interfaces: {e}")
            return []

    def _find_tshark(self):
        """Tìm đường dẫn tshark."""
        path = shutil.which("tshark")
        if path:
            return path
        # Thử các đường dẫn phổ biến
        for p in ["/usr/bin/tshark", "/usr/local/bin/tshark",
                   "C:\\Program Files\\Wireshark\\tshark.exe"]:
            if shutil.which(p) or __import__("os").path.isfile(p):
                return p
        return None

    def start(self, interface=None):
        """Bắt đầu bắt gói tin bằng tshark."""
        if self.is_running:
            return {"error": "Đang chạy rồi"}

        tshark = self._find_tshark()
        if not tshark:
            return {"error": "Không tìm thấy tshark. Hãy cài Wireshark/tshark trước."}

        if interface:
            self.interface = interface

        self._reset_stats()
        self.is_running = True
        self.start_time = time.time()
        self._last_second = int(self.start_time)

        self._thread = threading.Thread(target=self._tshark_loop, args=(tshark,), daemon=True)
        self._thread.start()

        return {"status": "started", "interface": self.interface or "default"}

    def stop(self):
        """Dừng tshark."""
        if not self.is_running:
            return {"error": "Chưa chạy"}

        self.is_running = False
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=3)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        return {"status": "stopped", "total_packets": self.total_packets}

    def _reset_stats(self):
        """Reset toàn bộ thống kê."""
        with self._lock:
            self.total_packets = 0
            self.total_bytes = 0
            self.protocol_counts.clear()
            self.src_ip_counts.clear()
            self.dst_port_counts.clear()
            self.src_ip_protocol.clear()
            self.pps_timeline.clear()
            self._current_second_count = 0
            self._syn_per_second.clear()
            self._udp_per_second.clear()
            self._icmp_per_second.clear()
            self._http_per_second.clear()
            self.alerts.clear()
            self._alert_cooldown.clear()
            self.recent_packets.clear()
            self.http_methods.clear()
            self.total_http_requests = 0

    def _tshark_loop(self, tshark):
        """Chạy tshark và parse output."""
        # tshark fields:
        # -e frame.time_epoch    : timestamp
        # -e ip.src              : source IP
        # -e ip.dst              : dest IP
        # -e _ws.col.Protocol    : protocol name
        # -e frame.len           : packet size
        # -e tcp.srcport         : TCP src port
        # -e tcp.dstport         : TCP dst port
        # -e udp.srcport         : UDP src port
        # -e udp.dstport         : UDP dst port
        # -e tcp.flags           : TCP flags hex
        # -e http.request.method : HTTP method
        cmd = [
            tshark,
            "-l",  # line-buffered output
            "-T", "fields",
            "-E", "separator=|",
            "-E", "occurrence=f",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "_ws.col.Protocol",
            "-e", "frame.len",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "tcp.flags",
            "-e", "http.request.method",
        ]

        if self.interface:
            cmd.extend(["-i", self.interface])

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            for line in iter(self._process.stdout.readline, ""):
                if not self.is_running:
                    break
                line = line.strip()
                if line:
                    self._parse_tshark_line(line)

        except Exception as e:
            print(f"[LiveSniffer] Lỗi tshark: {e}")
        finally:
            self.is_running = False
            if self._process:
                try:
                    self._process.terminate()
                except Exception:
                    pass

    def _parse_tshark_line(self, line):
        """Parse một dòng output từ tshark."""
        try:
            fields = line.split("|")
            if len(fields) < 11:
                return

            timestamp_str = fields[0]
            src_ip = fields[1]
            dst_ip = fields[2]
            proto_name = fields[3]
            frame_len = fields[4]
            tcp_sport = fields[5]
            tcp_dport = fields[6]
            udp_sport = fields[7]
            udp_dport = fields[8]
            tcp_flags_hex = fields[9]
            http_method = fields[10]

            # Bỏ qua packet không có IP
            if not src_ip or not dst_ip:
                return

            now = time.time()
            current_second = int(now)

            # Parse size
            try:
                pkt_size = int(frame_len)
            except (ValueError, TypeError):
                pkt_size = 0

            # Xác định protocol
            proto_upper = proto_name.upper() if proto_name else "OTHER"
            if "TCP" in proto_upper or "HTTP" in proto_upper or "TLS" in proto_upper:
                protocol = "TCP"
            elif "UDP" in proto_upper or "DNS" in proto_upper:
                protocol = "UDP"
            elif "ICMP" in proto_upper:
                protocol = "ICMP"
            elif "ARP" in proto_upper:
                return  # Bỏ qua ARP
            else:
                protocol = "OTHER"

            # Ports
            src_port = None
            dst_port = None
            if tcp_sport:
                try: src_port = int(tcp_sport)
                except: pass
            if tcp_dport:
                try: dst_port = int(tcp_dport)
                except: pass
            if not src_port and udp_sport:
                try: src_port = int(udp_sport)
                except: pass
            if not dst_port and udp_dport:
                try: dst_port = int(udp_dport)
                except: pass

            # TCP SYN check (flags hex: 0x0002 = SYN only)
            is_syn = False
            if tcp_flags_hex:
                try:
                    flags_int = int(tcp_flags_hex, 16)
                    # SYN=0x02, ACK=0x10. SYN without ACK
                    is_syn = (flags_int & 0x02) != 0 and (flags_int & 0x10) == 0
                except (ValueError, TypeError):
                    pass

            # HTTP check
            is_http = bool(http_method and http_method.strip())
            http_meth = http_method.strip() if is_http else None

            with self._lock:
                self.total_packets += 1
                self.total_bytes += pkt_size

                # Timeline PPS
                if current_second != self._last_second:
                    self.pps_timeline.append(self._current_second_count)
                    self._current_second_count = 0
                    self._cleanup_old_seconds(current_second)
                    self._last_second = current_second
                self._current_second_count += 1

                # Thống kê
                self.protocol_counts[protocol] += 1
                self.src_ip_counts[src_ip] += 1
                self.src_ip_protocol[src_ip][protocol] += 1
                if dst_port:
                    self.dst_port_counts[dst_port] += 1

                # Per-second detection
                if is_syn:
                    self._syn_per_second[current_second][src_ip] += 1
                if protocol == "UDP":
                    self._udp_per_second[current_second][src_ip] += 1
                if protocol == "ICMP":
                    self._icmp_per_second[current_second][src_ip] += 1
                if is_http:
                    self._http_per_second[current_second][src_ip] += 1
                    self.http_methods[http_meth] += 1
                    self.total_http_requests += 1

                # Lưu packet gần nhất
                time_str = datetime.now().strftime("%H:%M:%S")
                info = ""
                if is_syn:
                    info = "SYN"
                elif is_http and http_meth:
                    info = http_meth
                elif proto_name:
                    info = proto_name

                self.recent_packets.append({
                    "time": time_str,
                    "src": src_ip,
                    "dst": dst_ip,
                    "proto": protocol,
                    "size": pkt_size,
                    "sport": src_port,
                    "dport": dst_port,
                    "info": info,
                })

                # Kiểm tra DDoS
                self._check_ddos(current_second, src_ip, is_syn, protocol, is_http)

        except Exception as e:
            pass  # Bỏ qua lỗi parse

    def _check_ddos(self, current_second, src_ip, is_syn, protocol, is_http):
        """Kiểm tra ngưỡng DDoS."""
        now = time.time()
        checks = []
        if is_syn:
            count = self._syn_per_second[current_second][src_ip]
            checks.append(("SYN_FLOOD", count, self.thresholds["SYN_FLOOD"]))
        if protocol == "UDP":
            count = self._udp_per_second[current_second][src_ip]
            checks.append(("UDP_FLOOD", count, self.thresholds["UDP_FLOOD"]))
        if protocol == "ICMP":
            count = self._icmp_per_second[current_second][src_ip]
            checks.append(("ICMP_FLOOD", count, self.thresholds["ICMP_FLOOD"]))
        if is_http:
            count = self._http_per_second[current_second][src_ip]
            checks.append(("HTTP_FLOOD", count, self.thresholds["HTTP_FLOOD"]))

        for attack_type, count, threshold in checks:
            if count >= threshold:
                cooldown_key = (attack_type, src_ip)
                last_alert = self._alert_cooldown.get(cooldown_key, 0)
                if now - last_alert >= 3:
                    ratio = round(count / threshold, 2)
                    severity = self._determine_severity(count, threshold)
                    self.alerts.append({
                        "id": len(self.alerts),
                        "time": datetime.now().strftime("%H:%M:%S"),
                        "attack_type": attack_type,
                        "source_ip": src_ip,
                        "packet_count": count,
                        "threshold": threshold,
                        "ratio": ratio,
                        "severity": severity,
                    })
                    self._alert_cooldown[cooldown_key] = now

    def _determine_severity(self, count, threshold):
        ratio = count / threshold if threshold > 0 else 0
        if ratio >= config.SEVERITY_LEVELS["CRITICAL"]:
            return "CRITICAL"
        elif ratio >= config.SEVERITY_LEVELS["HIGH"]:
            return "HIGH"
        elif ratio >= config.SEVERITY_LEVELS["MEDIUM"]:
            return "MEDIUM"
        return "LOW"

    def _cleanup_old_seconds(self, current_second):
        cutoff = current_second - 10
        for store in [self._syn_per_second, self._udp_per_second,
                      self._icmp_per_second, self._http_per_second]:
            old_keys = [k for k in store if k < cutoff]
            for k in old_keys:
                del store[k]

    def get_live_data(self):
        """Trả về snapshot dữ liệu hiện tại."""
        with self._lock:
            elapsed = time.time() - self.start_time if self.start_time else 0
            pps_list = list(self.pps_timeline)
            pps_list.append(self._current_second_count)

            total_pkts = sum(self.src_ip_counts.values()) or 1
            top_ips = []
            for ip, count in self.src_ip_counts.most_common(10):
                top_ips.append({
                    "ip": ip, "count": count,
                    "percentage": round((count / total_pkts) * 100, 2),
                    "protocols": dict(self.src_ip_protocol[ip]),
                })

            proto_total = sum(self.protocol_counts.values()) or 1
            protocol_dist = {}
            for proto, count in self.protocol_counts.most_common():
                protocol_dist[proto] = {
                    "count": count,
                    "percentage": round((count / proto_total) * 100, 2),
                }

            risk = "SAFE"
            if self.alerts:
                sevs = [a["severity"] for a in self.alerts]
                if "CRITICAL" in sevs: risk = "CRITICAL"
                elif "HIGH" in sevs: risk = "HIGH"
                elif "MEDIUM" in sevs: risk = "MEDIUM"
                elif "LOW" in sevs: risk = "LOW"

            avg_pps = round(sum(pps_list) / len(pps_list), 1) if pps_list else 0
            max_pps = max(pps_list) if pps_list else 0

            return {
                "is_running": self.is_running,
                "interface": self.interface or "default",
                "elapsed_seconds": round(elapsed, 1),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_bytes_formatted": self._format_size(self.total_bytes),
                "avg_pps": avg_pps,
                "max_pps": max_pps,
                "current_pps": self._current_second_count,
                "pps_timeline": pps_list[-60:],
                "protocol_distribution": protocol_dist,
                "top_source_ips": top_ips,
                "risk_level": risk,
                "total_alerts": len(self.alerts),
                "alerts": list(self.alerts)[-20:],
                "recent_packets": list(self.recent_packets)[-30:],
                "http_stats": {"methods": dict(self.http_methods), "total_requests": self.total_http_requests},
                "unique_src_ips": len(self.src_ip_counts),
            }

    @staticmethod
    def _format_size(size_bytes):
        for unit in ["B", "KB", "MB", "GB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} TB"
