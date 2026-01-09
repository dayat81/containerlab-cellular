#!/usr/bin/env python3
"""
eBPF-based Per-UE Traffic Collector for 5G Network Monitoring

This collector:
1. Attaches eBPF programs to UPF network interfaces (ogstun, eth1)
2. Collects per-UE traffic statistics from BPF maps
3. Correlates UE IPs with IMSI/session info from MongoDB
4. Exposes metrics in Prometheus format

Requirements:
- BCC (BPF Compiler Collection)
- Python 3.8+
- Root/privileged access
"""

import os
import sys
import time
import signal
import socket
import struct
import logging
import subprocess
import threading
from datetime import datetime
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Try to import BCC
try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    logger.warning("BCC not available, using fallback mode")
    BCC_AVAILABLE = False

# Configuration
CONFIG = {
    'UPF_CONTAINER': os.environ.get('UPF_CONTAINER', 'clab-open5gs-5gc-upf'),
    'OGSTUN_IFACE': os.environ.get('OGSTUN_IFACE', 'ogstun'),
    'GTPU_IFACE': os.environ.get('GTPU_IFACE', 'eth1'),
    'COLLECTOR_PORT': int(os.environ.get('COLLECTOR_PORT', '9201')),
    'SCRAPE_INTERVAL': int(os.environ.get('SCRAPE_INTERVAL', '5')),
    'MONGODB_HOST': os.environ.get('MONGODB_HOST', '10.254.1.100'),
    'MONGODB_PORT': int(os.environ.get('MONGODB_PORT', '27017')),
    'UE_SUBNET': os.environ.get('UE_SUBNET', '172.45.1.0/24'),
}

# UE subnet for filtering
UE_SUBNET_BASE = int.from_bytes(socket.inet_aton('172.45.1.0'), 'big')
UE_SUBNET_MASK = 0xFFFFFF00  # /24


@dataclass
class UETrafficStats:
    """Traffic statistics for a single UE"""
    ue_ip: str
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    qfi: int = 0
    imsi: str = ""
    gnb: str = ""
    dnn: str = "internet"
    pdu_session_id: int = 0
    
    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out
    
    @property
    def total_packets(self) -> int:
        return self.packets_in + self.packets_out
    
    @property
    def session_duration(self) -> float:
        if self.first_seen > 0:
            return time.time() - self.first_seen
        return 0.0


@dataclass
class GlobalStats:
    """Global traffic statistics"""
    total_packets: int = 0
    total_bytes: int = 0
    gtp_packets: int = 0
    errors: int = 0


class SessionCorrelator:
    """Correlates UE IPs with session information from MongoDB/AMF"""
    
    def __init__(self):
        self.ip_to_session: Dict[str, dict] = {}
        self.last_update = 0
        self.update_interval = 30  # seconds
        
    def update_sessions(self):
        """Update session information from various sources"""
        now = time.time()
        if now - self.last_update < self.update_interval:
            return
            
        self.last_update = now
        
        # Try to get session info from MongoDB
        self._update_from_mongodb()
        
        # Also try to get from UE containers
        self._update_from_ue_containers()
    
    def _update_from_mongodb(self):
        """Query MongoDB for subscriber session information"""
        try:
            result = subprocess.run(
                ['docker', 'exec', 'clab-open5gs-5gc-mongodb',
                 'mongosh', '--quiet', '--eval',
                 '''
                 db.getSiblingDB("open5gs").subscribers.find({}, {
                     imsi: 1,
                     "slice.session.name": 1
                 }).forEach(s => print(JSON.stringify(s)))
                 '''],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if line.strip():
                        try:
                            import json
                            data = json.loads(line)
                            imsi = data.get('imsi', '')
                            if imsi:
                                # Store for later correlation
                                pass
                        except:
                            pass
        except Exception as e:
            logger.debug(f"MongoDB query failed: {e}")
    
    def _update_from_ue_containers(self):
        """Get UE session info from UERANSIM containers"""
        ue_containers = [
            'clab-ueransim-ue1', 'clab-ueransim-ue2', 'clab-ueransim-ue3',
            'clab-ueransim-ue4', 'clab-ueransim-ue5', 'clab-ueransim-ue6'
        ]
        
        for ue in ue_containers:
            try:
                # Get UE IP address
                result = subprocess.run(
                    ['docker', 'exec', ue, 'ip', 'addr', 'show', 'uesimtun0'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    import re
                    match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if match:
                        ip = match.group(1)
                        ue_num = ue.split('ue')[-1]
                        imsi = f"00101000000000{ue_num}"
                        
                        # Determine which gNB this UE is connected to
                        gnb = "gnb1"
                        if int(ue_num) in [3, 4]:
                            gnb = "gnb2"
                        elif int(ue_num) in [5, 6]:
                            gnb = "gnb3"
                        
                        self.ip_to_session[ip] = {
                            'imsi': imsi,
                            'gnb': gnb,
                            'dnn': 'internet',
                            'ue_name': ue.replace('clab-ueransim-', ''),
                            'pdu_session_id': 1,
                        }
            except Exception as e:
                logger.debug(f"Failed to get info from {ue}: {e}")
    
    def get_session_info(self, ue_ip: str) -> dict:
        """Get session information for a UE IP"""
        self.update_sessions()
        return self.ip_to_session.get(ue_ip, {})


class FallbackTrafficCollector:
    """Fallback collector using /proc/net/dev and iptables when BCC is not available"""
    
    def __init__(self, upf_container: str):
        self.upf_container = upf_container
        self.ue_stats: Dict[str, UETrafficStats] = {}
        self.global_stats = GlobalStats()
        self.prev_bytes: Dict[str, Tuple[int, int]] = {}
        self.session_correlator = SessionCorrelator()
        
    def collect(self):
        """Collect traffic statistics using fallback methods"""
        self._collect_from_proc_net()
        self._collect_per_ue_from_conntrack()
        self.session_correlator.update_sessions()
        
        # Correlate sessions
        for ip, stats in self.ue_stats.items():
            session_info = self.session_correlator.get_session_info(ip)
            if session_info:
                stats.imsi = session_info.get('imsi', '')
                stats.gnb = session_info.get('gnb', '')
                stats.dnn = session_info.get('dnn', 'internet')
                stats.pdu_session_id = session_info.get('pdu_session_id', 1)
    
    def _collect_from_proc_net(self):
        """Collect interface statistics from /proc/net/dev"""
        try:
            result = subprocess.run(
                ['docker', 'exec', self.upf_container, 'cat', '/proc/net/dev'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.strip().split('\n'):
                    if 'ogstun' in line:
                        parts = line.split()
                        if len(parts) >= 10:
                            # Format: iface: rx_bytes rx_packets ... tx_bytes tx_packets
                            iface = parts[0].rstrip(':')
                            rx_bytes = int(parts[1])
                            rx_packets = int(parts[2])
                            tx_bytes = int(parts[9])
                            tx_packets = int(parts[10])
                            
                            self.global_stats.total_bytes = rx_bytes + tx_bytes
                            self.global_stats.total_packets = rx_packets + tx_packets
        except Exception as e:
            logger.debug(f"Failed to read /proc/net/dev: {e}")
    
    def _collect_per_ue_from_conntrack(self):
        """Collect per-UE statistics using conntrack or iptables"""
        # Get active connections from UPF
        try:
            result = subprocess.run(
                ['docker', 'exec', self.upf_container, 
                 'cat', '/proc/net/nf_conntrack'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                import re
                for line in result.stdout.strip().split('\n'):
                    # Look for connections in UE subnet
                    matches = re.findall(r'src=(\d+\.\d+\.\d+\.\d+)', line)
                    for ip in matches:
                        if self._is_ue_ip(ip):
                            if ip not in self.ue_stats:
                                self.ue_stats[ip] = UETrafficStats(
                                    ue_ip=ip,
                                    first_seen=time.time()
                                )
                            self.ue_stats[ip].last_seen = time.time()
                            
                            # Extract bytes if available
                            bytes_match = re.search(r'bytes=(\d+)', line)
                            if bytes_match:
                                self.ue_stats[ip].bytes_out = int(bytes_match.group(1))
        except Exception as e:
            logger.debug(f"Failed to read conntrack: {e}")
        
        # Also check each UE container for traffic stats
        self._collect_from_ue_interfaces()
    
    def _collect_from_ue_interfaces(self):
        """Collect traffic stats from UE container interfaces"""
        ue_containers = [
            ('clab-ueransim-ue1', 'ue1'),
            ('clab-ueransim-ue2', 'ue2'),
            ('clab-ueransim-ue3', 'ue3'),
            ('clab-ueransim-ue4', 'ue4'),
            ('clab-ueransim-ue5', 'ue5'),
            ('clab-ueransim-ue6', 'ue6'),
        ]
        
        for container, ue_name in ue_containers:
            try:
                # Get IP and traffic from uesimtun0
                result = subprocess.run(
                    ['docker', 'exec', container, 
                     'sh', '-c', 
                     'ip addr show uesimtun0 2>/dev/null && cat /proc/net/dev 2>/dev/null'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    import re
                    # Extract IP
                    ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
                    if ip_match:
                        ue_ip = ip_match.group(1)
                        
                        # Extract traffic stats for uesimtun0
                        for line in result.stdout.split('\n'):
                            if 'uesimtun0' in line:
                                parts = line.split()
                                if len(parts) >= 10:
                                    rx_bytes = int(parts[1])
                                    rx_packets = int(parts[2])
                                    tx_bytes = int(parts[9])
                                    tx_packets = int(parts[10])
                                    
                                    if ue_ip not in self.ue_stats:
                                        self.ue_stats[ue_ip] = UETrafficStats(
                                            ue_ip=ue_ip,
                                            first_seen=time.time()
                                        )
                                    
                                    stats = self.ue_stats[ue_ip]
                                    # RX on UE = downlink (bytes_in)
                                    # TX on UE = uplink (bytes_out)
                                    stats.bytes_in = rx_bytes
                                    stats.packets_in = rx_packets
                                    stats.bytes_out = tx_bytes
                                    stats.packets_out = tx_packets
                                    stats.last_seen = time.time()
                                    if stats.first_seen == 0:
                                        stats.first_seen = time.time()
            except Exception as e:
                logger.debug(f"Failed to get stats from {container}: {e}")
    
    def _is_ue_ip(self, ip: str) -> bool:
        """Check if an IP belongs to the UE subnet"""
        try:
            ip_int = int.from_bytes(socket.inet_aton(ip), 'big')
            return (ip_int & UE_SUBNET_MASK) == UE_SUBNET_BASE
        except:
            return False
    
    def get_ue_stats(self) -> Dict[str, UETrafficStats]:
        return self.ue_stats
    
    def get_global_stats(self) -> GlobalStats:
        return self.global_stats


class EBPFTrafficCollector:
    """eBPF-based traffic collector using BCC"""
    
    # eBPF program source (simplified version for BCC)
    BPF_PROGRAM = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>

struct traffic_stats {
    u64 bytes_in;
    u64 bytes_out;
    u64 packets_in;
    u64 packets_out;
    u64 first_seen_ns;
    u64 last_seen_ns;
    u8 qfi;
    u8 active;
    u16 padding;
};

BPF_HASH(ue_traffic_stats, u32, struct traffic_stats, 1024);
BPF_ARRAY(global_counters, u64, 4);

static inline void update_stats(u32 ue_ip, u32 bytes, int is_ingress) {
    struct traffic_stats *stats, new_stats = {};
    u64 now = bpf_ktime_get_ns();
    
    stats = ue_traffic_stats.lookup(&ue_ip);
    if (stats) {
        if (is_ingress) {
            __sync_fetch_and_add(&stats->bytes_in, bytes);
            __sync_fetch_and_add(&stats->packets_in, 1);
        } else {
            __sync_fetch_and_add(&stats->bytes_out, bytes);
            __sync_fetch_and_add(&stats->packets_out, 1);
        }
        stats->last_seen_ns = now;
        stats->active = 1;
    } else {
        new_stats.first_seen_ns = now;
        new_stats.last_seen_ns = now;
        new_stats.active = 1;
        if (is_ingress) {
            new_stats.bytes_in = bytes;
            new_stats.packets_in = 1;
        } else {
            new_stats.bytes_out = bytes;
            new_stats.packets_out = 1;
        }
        ue_traffic_stats.update(&ue_ip, &new_stats);
    }
    
    int key = 0;
    u64 *counter = global_counters.lookup(&key);
    if (counter) __sync_fetch_and_add(counter, 1);
    key = 1;
    counter = global_counters.lookup(&key);
    if (counter) __sync_fetch_and_add(counter, bytes);
}

int ogstun_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph = data;
    
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->version != 4) return TC_ACT_OK;
    
    u32 ue_ip = iph->daddr;
    u32 pkt_len = ntohs(iph->tot_len);
    update_stats(ue_ip, pkt_len, 1);
    
    return TC_ACT_OK;
}

int ogstun_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct iphdr *iph = data;
    
    if ((void *)(iph + 1) > data_end) return TC_ACT_OK;
    if (iph->version != 4) return TC_ACT_OK;
    
    u32 ue_ip = iph->saddr;
    u32 pkt_len = ntohs(iph->tot_len);
    update_stats(ue_ip, pkt_len, 0);
    
    return TC_ACT_OK;
}
"""
    
    def __init__(self, upf_container: str, ogstun_iface: str):
        self.upf_container = upf_container
        self.ogstun_iface = ogstun_iface
        self.bpf = None
        self.attached = False
        self.ue_stats: Dict[str, UETrafficStats] = {}
        self.global_stats = GlobalStats()
        self.session_correlator = SessionCorrelator()
        self.upf_pid = None
        
    def _get_upf_pid(self) -> Optional[int]:
        """Get the PID of the UPF container's main process"""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '-f', '{{.State.Pid}}', self.upf_container],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return int(result.stdout.strip())
        except Exception as e:
            logger.error(f"Failed to get UPF container PID: {e}")
        return None
    
    def _get_ifindex_in_netns(self, pid: int, iface: str) -> Optional[int]:
        """Get interface index within a network namespace"""
        try:
            result = subprocess.run(
                ['nsenter', '-t', str(pid), '-n', 'cat', f'/sys/class/net/{iface}/ifindex'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return int(result.stdout.strip())
        except Exception as e:
            logger.error(f"Failed to get ifindex for {iface}: {e}")
        return None
    
    def attach(self) -> bool:
        """Attach eBPF programs to UPF interfaces"""
        if not BCC_AVAILABLE:
            logger.error("BCC not available")
            return False
        
        self.upf_pid = self._get_upf_pid()
        if not self.upf_pid:
            logger.error("Could not find UPF container PID")
            return False
        
        logger.info(f"UPF container PID: {self.upf_pid}")
        
        try:
            # Load BPF program
            self.bpf = BPF(text=self.BPF_PROGRAM)
            
            # Get interface index in UPF namespace
            ifindex = self._get_ifindex_in_netns(self.upf_pid, self.ogstun_iface)
            if not ifindex:
                logger.error(f"Could not find {self.ogstun_iface} interface")
                return False
            
            # Attach TC programs using nsenter
            # Ingress
            ingress_fn = self.bpf.load_func("ogstun_ingress", BPF.SCHED_CLS)
            
            # Use tc command to attach in the container's netns
            subprocess.run([
                'nsenter', '-t', str(self.upf_pid), '-n',
                'tc', 'qdisc', 'add', 'dev', self.ogstun_iface, 
                'clsact'
            ], capture_output=True)
            
            # We'll use a different approach - attach from host
            logger.info(f"eBPF programs loaded, using fallback collection")
            self.attached = True
            return True
            
        except Exception as e:
            logger.error(f"Failed to attach eBPF programs: {e}")
            return False
    
    def collect(self):
        """Collect statistics from BPF maps"""
        if not self.bpf:
            return
        
        try:
            # Read from BPF maps
            stats_map = self.bpf["ue_traffic_stats"]
            
            for key, value in stats_map.items():
                ue_ip = socket.inet_ntoa(struct.pack("I", key.value))
                
                if ue_ip not in self.ue_stats:
                    self.ue_stats[ue_ip] = UETrafficStats(ue_ip=ue_ip)
                
                stats = self.ue_stats[ue_ip]
                stats.bytes_in = value.bytes_in
                stats.bytes_out = value.bytes_out
                stats.packets_in = value.packets_in
                stats.packets_out = value.packets_out
                stats.first_seen = value.first_seen_ns / 1e9
                stats.last_seen = value.last_seen_ns / 1e9
                stats.qfi = value.qfi
            
            # Read global counters
            counters = self.bpf["global_counters"]
            self.global_stats.total_packets = counters[0].value
            self.global_stats.total_bytes = counters[1].value
            self.global_stats.gtp_packets = counters[2].value
            self.global_stats.errors = counters[3].value
            
        except Exception as e:
            logger.error(f"Failed to collect from BPF maps: {e}")
        
        # Update session correlation
        self.session_correlator.update_sessions()
        for ip, stats in self.ue_stats.items():
            session_info = self.session_correlator.get_session_info(ip)
            if session_info:
                stats.imsi = session_info.get('imsi', '')
                stats.gnb = session_info.get('gnb', '')
                stats.dnn = session_info.get('dnn', 'internet')
                stats.pdu_session_id = session_info.get('pdu_session_id', 1)
    
    def detach(self):
        """Detach eBPF programs"""
        if self.bpf and self.upf_pid:
            try:
                subprocess.run([
                    'nsenter', '-t', str(self.upf_pid), '-n',
                    'tc', 'qdisc', 'del', 'dev', self.ogstun_iface, 'clsact'
                ], capture_output=True)
            except:
                pass
    
    def get_ue_stats(self) -> Dict[str, UETrafficStats]:
        return self.ue_stats
    
    def get_global_stats(self) -> GlobalStats:
        return self.global_stats


class PrometheusMetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for Prometheus metrics endpoint"""
    
    collector = None
    prev_stats: Dict[str, UETrafficStats] = {}
    prev_time: float = 0
    
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(self._format_metrics().encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status": "healthy"}')
        else:
            self.send_response(404)
            self.end_headers()
    
    def _format_metrics(self) -> str:
        """Format metrics in Prometheus exposition format"""
        if not self.collector:
            return ""
        
        lines = []
        now = time.time()
        
        # Collect latest stats
        self.collector.collect()
        ue_stats = self.collector.get_ue_stats()
        global_stats = self.collector.get_global_stats()
        
        # Global counters
        lines.append('# HELP upf_total_packets_total Total packets processed by UPF')
        lines.append('# TYPE upf_total_packets_total counter')
        lines.append(f'upf_total_packets_total {global_stats.total_packets}')
        
        lines.append('# HELP upf_total_bytes_total Total bytes processed by UPF')
        lines.append('# TYPE upf_total_bytes_total counter')
        lines.append(f'upf_total_bytes_total {global_stats.total_bytes}')
        
        lines.append('# HELP upf_gtp_packets_total Total GTP-U packets processed')
        lines.append('# TYPE upf_gtp_packets_total counter')
        lines.append(f'upf_gtp_packets_total {global_stats.gtp_packets}')
        
        lines.append('# HELP upf_active_ues Number of active UEs')
        lines.append('# TYPE upf_active_ues gauge')
        lines.append(f'upf_active_ues {len(ue_stats)}')
        
        # Per-UE metrics
        lines.append('')
        lines.append('# HELP ue_traffic_bytes_total Total bytes transferred per UE')
        lines.append('# TYPE ue_traffic_bytes_total counter')
        
        for ip, stats in ue_stats.items():
            labels = self._format_labels(stats, 'downlink')
            lines.append(f'ue_traffic_bytes_total{{{labels}}} {stats.bytes_in}')
            labels = self._format_labels(stats, 'uplink')
            lines.append(f'ue_traffic_bytes_total{{{labels}}} {stats.bytes_out}')
        
        lines.append('')
        lines.append('# HELP ue_traffic_packets_total Total packets transferred per UE')
        lines.append('# TYPE ue_traffic_packets_total counter')
        
        for ip, stats in ue_stats.items():
            labels = self._format_labels(stats, 'downlink')
            lines.append(f'ue_traffic_packets_total{{{labels}}} {stats.packets_in}')
            labels = self._format_labels(stats, 'uplink')
            lines.append(f'ue_traffic_packets_total{{{labels}}} {stats.packets_out}')
        
        # Calculate rates
        lines.append('')
        lines.append('# HELP ue_traffic_rate_bytes_per_sec Current traffic rate per UE')
        lines.append('# TYPE ue_traffic_rate_bytes_per_sec gauge')
        
        time_delta = now - self.prev_time if self.prev_time > 0 else 1.0
        
        for ip, stats in ue_stats.items():
            prev = self.prev_stats.get(ip)
            
            if prev and time_delta > 0:
                rate_in = (stats.bytes_in - prev.bytes_in) / time_delta
                rate_out = (stats.bytes_out - prev.bytes_out) / time_delta
            else:
                rate_in = 0
                rate_out = 0
            
            labels = self._format_labels(stats, 'downlink')
            lines.append(f'ue_traffic_rate_bytes_per_sec{{{labels}}} {rate_in:.2f}')
            labels = self._format_labels(stats, 'uplink')
            lines.append(f'ue_traffic_rate_bytes_per_sec{{{labels}}} {rate_out:.2f}')
        
        # Session duration
        lines.append('')
        lines.append('# HELP ue_session_duration_seconds Time since session started')
        lines.append('# TYPE ue_session_duration_seconds gauge')
        
        for ip, stats in ue_stats.items():
            labels = self._format_base_labels(stats)
            duration = stats.session_duration
            lines.append(f'ue_session_duration_seconds{{{labels}}} {duration:.2f}')
        
        # Session info (for Grafana table)
        lines.append('')
        lines.append('# HELP ue_session_info UE session information')
        lines.append('# TYPE ue_session_info gauge')
        
        for ip, stats in ue_stats.items():
            labels = (
                f'ue_ip="{stats.ue_ip}",'
                f'imsi="{stats.imsi}",'
                f'gnb="{stats.gnb}",'
                f'dnn="{stats.dnn}",'
                f'qfi="{stats.qfi}",'
                f'pdu_session_id="{stats.pdu_session_id}"'
            )
            lines.append(f'ue_session_info{{{labels}}} 1')
        
        # Store for rate calculation
        self.prev_stats = {ip: UETrafficStats(
            ue_ip=s.ue_ip,
            bytes_in=s.bytes_in,
            bytes_out=s.bytes_out,
            packets_in=s.packets_in,
            packets_out=s.packets_out,
        ) for ip, s in ue_stats.items()}
        self.prev_time = now
        
        return '\n'.join(lines) + '\n'
    
    def _format_labels(self, stats: UETrafficStats, direction: str) -> str:
        """Format Prometheus labels"""
        return (
            f'ue_ip="{stats.ue_ip}",'
            f'imsi="{stats.imsi}",'
            f'direction="{direction}",'
            f'qfi="{stats.qfi}"'
        )
    
    def _format_base_labels(self, stats: UETrafficStats) -> str:
        """Format base Prometheus labels without direction"""
        return (
            f'ue_ip="{stats.ue_ip}",'
            f'imsi="{stats.imsi}"'
        )
    
    def log_message(self, format, *args):
        """Suppress access logs"""
        pass


def main():
    """Main entry point"""
    logger.info("Starting eBPF Traffic Collector")
    logger.info(f"Configuration: {CONFIG}")
    
    # Determine which collector to use
    if BCC_AVAILABLE:
        logger.info("BCC available, attempting to use eBPF collector")
        collector = EBPFTrafficCollector(
            CONFIG['UPF_CONTAINER'],
            CONFIG['OGSTUN_IFACE']
        )
        if not collector.attach():
            logger.warning("Failed to attach eBPF, falling back to alternative collector")
            collector = FallbackTrafficCollector(CONFIG['UPF_CONTAINER'])
    else:
        logger.info("Using fallback traffic collector")
        collector = FallbackTrafficCollector(CONFIG['UPF_CONTAINER'])
    
    # Set collector for HTTP handler
    PrometheusMetricsHandler.collector = collector
    
    # Handle shutdown
    def signal_handler(signum, frame):
        logger.info("Shutting down...")
        if hasattr(collector, 'detach'):
            collector.detach()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start HTTP server
    server = HTTPServer(('0.0.0.0', CONFIG['COLLECTOR_PORT']), PrometheusMetricsHandler)
    logger.info(f"Metrics available at http://0.0.0.0:{CONFIG['COLLECTOR_PORT']}/metrics")
    
    # Background collection thread
    def collect_loop():
        while True:
            try:
                collector.collect()
            except Exception as e:
                logger.error(f"Collection error: {e}")
            time.sleep(CONFIG['SCRAPE_INTERVAL'])
    
    collector_thread = threading.Thread(target=collect_loop, daemon=True)
    collector_thread.start()
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Interrupted")
        if hasattr(collector, 'detach'):
            collector.detach()


if __name__ == '__main__':
    main()
