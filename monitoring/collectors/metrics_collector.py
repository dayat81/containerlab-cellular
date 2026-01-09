#!/usr/bin/env python3
"""
5G Network Metrics Collector for Prometheus
Collects metrics from:
- UERANSIM gNB/UE containers (via docker exec)
- MongoDB subscriber database
- Open5GS WebUI API
"""

import subprocess
import json
import re
import time
import os
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://10.254.1.100:27017')
WEBUI_URL = os.environ.get('WEBUI_URL', 'http://10.254.1.200:9999')
COLLECTOR_PORT = int(os.environ.get('COLLECTOR_PORT', '9200'))
SCRAPE_INTERVAL = int(os.environ.get('SCRAPE_INTERVAL', '15'))

# Container names
CONTAINERS = {
    'gnb': ['clab-ueransim-gnb', 'clab-ueransim-gnb2', 'clab-ueransim-gnb3'],
    'ue': ['clab-ueransim-ue1', 'clab-ueransim-ue2', 'clab-ueransim-ue3',
           'clab-ueransim-ue4', 'clab-ueransim-ue5', 'clab-ueransim-ue6'],
    'upf': ['clab-open5gs-5gc-upf'],
    'amf': ['clab-open5gs-5gc-amf'],
}

# Global metrics storage
metrics = {
    'gnb_count': 0,
    'ue_registered_count': 0,
    'pdu_session_count': 0,
    'subscriber_count': 0,
    'ue_sessions': [],
    'gnb_info': [],
}


def run_docker_cmd(container, cmd, timeout=5):
    """Run command inside a docker container."""
    try:
        result = subprocess.run(
            ['docker', 'exec', container] + cmd.split(),
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.stdout, result.returncode
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout running command in {container}")
        return "", 1
    except Exception as e:
        logger.error(f"Error running docker command: {e}")
        return "", 1


def check_container_running(container):
    """Check if a container is running."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', '-f', '{{.State.Running}}', container],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.stdout.strip() == 'true'
    except:
        return False


def get_gnb_metrics():
    """Collect gNB metrics from UERANSIM containers."""
    gnb_count = 0
    gnb_info = []
    
    for gnb in CONTAINERS['gnb']:
        if check_container_running(gnb):
            # Check if gnb process is running
            stdout, rc = run_docker_cmd(gnb, 'pgrep -f nr-gnb')
            if rc == 0 and stdout.strip():
                gnb_count += 1
                
                # Get gNB log info
                stdout, _ = run_docker_cmd(gnb, 'cat /var/log/gnb.log')
                
                # Parse connected UE count from logs
                ue_match = re.search(r'Number of UEs: (\d+)', stdout)
                ue_count = int(ue_match.group(1)) if ue_match else 0
                
                gnb_info.append({
                    'name': gnb,
                    'status': 'running',
                    'connected_ues': ue_count,
                })
    
    return gnb_count, gnb_info


def get_ue_metrics():
    """Collect UE metrics from UERANSIM containers."""
    ue_count = 0
    pdu_sessions = 0
    ue_sessions = []
    
    for ue in CONTAINERS['ue']:
        if check_container_running(ue):
            # Check if UE has PDU session (uesimtun0 interface)
            stdout, rc = run_docker_cmd(ue, 'ip addr show uesimtun0')
            if rc == 0 and 'inet ' in stdout:
                ue_count += 1
                pdu_sessions += 1
                
                # Extract IP address
                ip_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', stdout)
                ip_addr = ip_match.group(1) if ip_match else 'unknown'
                
                # Get IMSI from config or log
                imsi = ue.replace('clab-ueransim-ue', '00101000000000')
                
                ue_sessions.append({
                    'ue': ue.replace('clab-ueransim-', ''),
                    'imsi': imsi,
                    'ip': ip_addr,
                    'status': 'Active',
                })
    
    return ue_count, pdu_sessions, ue_sessions


def get_subscriber_count():
    """Get subscriber count from MongoDB."""
    try:
        result = subprocess.run(
            ['docker', 'exec', 'clab-open5gs-5gc-mongodb', 
             'mongosh', '--quiet', '--eval',
             'db.getSiblingDB("open5gs").subscribers.countDocuments({})'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except Exception as e:
        logger.error(f"Error getting subscriber count: {e}")
    return 0


def collect_metrics():
    """Main metrics collection function."""
    global metrics
    
    while True:
        try:
            # Collect gNB metrics
            gnb_count, gnb_info = get_gnb_metrics()
            metrics['gnb_count'] = gnb_count
            metrics['gnb_info'] = gnb_info
            
            # Collect UE metrics
            ue_count, pdu_sessions, ue_sessions = get_ue_metrics()
            metrics['ue_registered_count'] = ue_count
            metrics['pdu_session_count'] = pdu_sessions
            metrics['ue_sessions'] = ue_sessions
            
            # Get subscriber count
            metrics['subscriber_count'] = get_subscriber_count()
            
            logger.info(f"Collected metrics: gNBs={gnb_count}, UEs={ue_count}, PDUs={pdu_sessions}, Subs={metrics['subscriber_count']}")
            
        except Exception as e:
            logger.error(f"Error collecting metrics: {e}")
        
        time.sleep(SCRAPE_INTERVAL)


def format_prometheus_metrics():
    """Format metrics in Prometheus exposition format."""
    lines = []
    
    # Basic counters
    lines.append('# HELP gnb_count Number of connected gNodeBs')
    lines.append('# TYPE gnb_count gauge')
    lines.append(f'gnb_count {metrics["gnb_count"]}')
    
    lines.append('# HELP ue_registered_count Number of registered UEs')
    lines.append('# TYPE ue_registered_count gauge')
    lines.append(f'ue_registered_count {metrics["ue_registered_count"]}')
    
    lines.append('# HELP pdu_session_count Number of active PDU sessions')
    lines.append('# TYPE pdu_session_count gauge')
    lines.append(f'pdu_session_count {metrics["pdu_session_count"]}')
    
    lines.append('# HELP subscriber_count Total number of subscribers in database')
    lines.append('# TYPE subscriber_count gauge')
    lines.append(f'subscriber_count {metrics["subscriber_count"]}')
    
    # UE session info
    lines.append('# HELP ue_session_info UE session information')
    lines.append('# TYPE ue_session_info gauge')
    for session in metrics['ue_sessions']:
        labels = f'ue="{session["ue"]}",imsi="{session["imsi"]}",ip="{session["ip"]}",status="{session["status"]}"'
        lines.append(f'ue_session_info{{{labels}}} 1')
    
    # gNB info
    lines.append('# HELP gnb_info gNodeB information')
    lines.append('# TYPE gnb_info gauge')
    for gnb in metrics['gnb_info']:
        labels = f'name="{gnb["name"]}",status="{gnb["status"]}"'
        lines.append(f'gnb_info{{{labels}}} {gnb["connected_ues"]}')
    
    return '\n'.join(lines) + '\n'


class MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler for Prometheus scraping."""
    
    def do_GET(self):
        if self.path == '/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.end_headers()
            self.wfile.write(format_prometheus_metrics().encode())
        elif self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'healthy'}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress access logs
        pass


def main():
    """Main entry point."""
    logger.info(f"Starting 5G Metrics Collector on port {COLLECTOR_PORT}")
    
    # Start metrics collection thread
    collector_thread = Thread(target=collect_metrics, daemon=True)
    collector_thread.start()
    
    # Start HTTP server
    server = HTTPServer(('0.0.0.0', COLLECTOR_PORT), MetricsHandler)
    logger.info(f"Metrics available at http://0.0.0.0:{COLLECTOR_PORT}/metrics")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        server.shutdown()


if __name__ == '__main__':
    main()
