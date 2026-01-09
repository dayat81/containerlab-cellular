#!/bin/bash
# Restore script for 5G Lab with Monitoring
# Created: 2026-01-09
# This script restores the full 5G lab environment including:
# - Open5GS 5G Core
# - UERANSIM gNBs and UEs
# - Prometheus + Grafana monitoring
# - iperf traffic generation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ACTION=${1:-start}

start_lab() {
    echo "============================================"
    echo "Starting 5G Lab Environment"
    echo "============================================"
    
    # Step 1: Deploy containerlab topology
    echo ""
    echo "[1/7] Deploying containerlab topology..."
    cd containerlab/5g-sa_open5gs_ueransim
    sudo containerlab deploy -t topologies/open5gs-5gc.yaml --reconfigure 2>/dev/null || \
    sudo containerlab deploy -t topologies/open5gs-5gc.yaml
    sudo containerlab deploy -t topologies/ueransim.yaml --reconfigure 2>/dev/null || \
    sudo containerlab deploy -t topologies/ueransim.yaml
    cd "$SCRIPT_DIR"
    
    echo ""
    echo "[2/7] Waiting for 5G Core to initialize (30 seconds)..."
    sleep 30
    
    # Step 2: Setup network IPs for monitoring
    echo ""
    echo "[3/7] Setting up network IPs for Prometheus access..."
    sudo ip addr add 10.254.1.254/24 dev br-sbi 2>/dev/null || true
    sudo ip addr add 10.100.1.254/24 dev br-n2-n3-n4 2>/dev/null || true
    sudo ip link set dev br-sbi up 2>/dev/null || true
    sudo ip link set dev br-n2-n3-n4 up 2>/dev/null || true
    
    # Step 3: Start monitoring stack
    echo ""
    echo "[4/7] Starting monitoring stack (Prometheus + Grafana)..."
    cd monitoring
    sudo docker-compose up -d
    cd "$SCRIPT_DIR"
    
    echo ""
    echo "[5/7] Waiting for services to stabilize (20 seconds)..."
    sleep 20
    
    # Step 4: Restart gNBs to establish NGAP connections
    echo ""
    echo "[6/7] Restarting gNBs and UEs for fresh connections..."
    for gnb in gnb gnb2 gnb3; do
        sudo docker exec clab-ueransim-${gnb} pkill -9 nr-gnb 2>/dev/null || true
        sleep 1
        sudo docker exec -d clab-ueransim-${gnb} bash -c "cd /UERANSIM && ./build/nr-gnb -c /gnb.yaml > /var/log/gnb.log 2>&1"
    done
    sleep 5
    
    for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
        sudo docker exec clab-ueransim-${ue} pkill -9 nr-ue 2>/dev/null || true
        sudo docker exec clab-ueransim-${ue} pkill -9 ping 2>/dev/null || true
        sudo docker exec clab-ueransim-${ue} pkill -9 iperf 2>/dev/null || true
        sleep 1
        sudo docker exec -d clab-ueransim-${ue} bash -c "cd /UERANSIM && ./build/nr-ue -c /ue.yaml > /var/log/ue.log 2>&1"
    done
    sleep 10
    
    # Step 5: Start background pings
    echo ""
    echo "[7/7] Starting background traffic (pings from all UEs)..."
    for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
        sudo docker exec -d clab-ueransim-${ue} ping -I uesimtun0 8.8.8.8
    done
    
    echo ""
    echo "============================================"
    echo "5G Lab Started Successfully!"
    echo "============================================"
    echo ""
    echo "Access URLs:"
    echo "  - Grafana:     http://34.34.219.137/grafana (admin/admin)"
    echo "  - Prometheus:  http://34.34.219.137/prometheus"
    echo "  - Open5GS WebUI: http://34.34.219.137 (admin/1423)"
    echo ""
    echo "To start iperf traffic test:"
    echo "  $0 iperf"
    echo ""
}

stop_lab() {
    echo "============================================"
    echo "Stopping 5G Lab Environment"
    echo "============================================"
    
    # Stop iperf
    pkill iperf 2>/dev/null || true
    
    # Stop monitoring
    echo "Stopping monitoring stack..."
    cd monitoring
    sudo docker-compose down 2>/dev/null || true
    cd "$SCRIPT_DIR"
    
    # Remove network IPs
    echo "Removing network IPs..."
    sudo ip addr del 10.254.1.254/24 dev br-sbi 2>/dev/null || true
    sudo ip addr del 10.100.1.254/24 dev br-n2-n3-n4 2>/dev/null || true
    
    # Destroy containerlab
    echo "Destroying containerlab topology..."
    cd containerlab/5g-sa_open5gs_ueransim
    sudo containerlab destroy -t topologies/ueransim.yaml 2>/dev/null || true
    sudo containerlab destroy -t topologies/open5gs-5gc.yaml 2>/dev/null || true
    cd "$SCRIPT_DIR"
    
    echo ""
    echo "5G Lab Stopped!"
}

start_iperf() {
    echo "Starting iperf traffic test..."
    
    # Install iperf if needed
    which iperf > /dev/null 2>&1 || sudo apt-get install -y -qq iperf
    
    # Start iperf server on host
    pkill iperf 2>/dev/null || true
    iperf -s -p 5001 &
    sleep 2
    
    HOST_IP=$(hostname -I | awk '{print $1}')
    echo "iperf server running on ${HOST_IP}:5001"
    
    # Install iperf on UEs if needed and start clients
    for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
        sudo docker exec clab-ueransim-${ue} which iperf > /dev/null 2>&1 || \
        sudo docker exec clab-ueransim-${ue} apt-get install -y -qq iperf 2>/dev/null
        
        sudo docker exec clab-ueransim-${ue} pkill iperf 2>/dev/null || true
        UE_IP=$(sudo docker exec clab-ueransim-${ue} ip addr show uesimtun0 2>/dev/null | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
        echo "Starting iperf on ${ue} (${UE_IP})..."
        sudo docker exec -d clab-ueransim-${ue} iperf -c ${HOST_IP} -p 5001 -t 0 -B ${UE_IP}
    done
    
    echo ""
    echo "iperf traffic test running! Check Grafana dashboard for traffic stats."
}

stop_iperf() {
    echo "Stopping iperf..."
    pkill iperf 2>/dev/null || true
    for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
        sudo docker exec clab-ueransim-${ue} pkill iperf 2>/dev/null || true
    done
    echo "iperf stopped."
}

status() {
    echo "============================================"
    echo "5G Lab Status"
    echo "============================================"
    echo ""
    
    echo "Container Status:"
    sudo docker ps --format "table {{.Names}}\t{{.Status}}" | grep -E "(clab-|grafana|prometheus)" | head -20
    
    echo ""
    echo "gNB Connections:"
    curl -s "http://10.254.1.1:9090/metrics" 2>/dev/null | grep -E "^ran_ue|^amf_session" || echo "  Unable to fetch AMF metrics"
    
    echo ""
    echo "UE Sessions:"
    curl -s "http://10.100.1.3:9090/metrics" 2>/dev/null | grep -E "upf_sessionnbr" || echo "  Unable to fetch UPF metrics"
    
    echo ""
    echo "Prometheus Targets:"
    curl -s "http://localhost:9090/prometheus/api/v1/targets" 2>/dev/null | \
        python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join([f\"  {t['labels']['job']}: {t['health']}\" for t in d['data']['activeTargets'][:10]]))" 2>/dev/null || \
        echo "  Unable to fetch Prometheus targets"
}

case "$ACTION" in
    start)
        start_lab
        ;;
    stop)
        stop_lab
        ;;
    restart)
        stop_lab
        sleep 5
        start_lab
        ;;
    iperf)
        start_iperf
        ;;
    stop-iperf)
        stop_iperf
        ;;
    status)
        status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|iperf|stop-iperf|status}"
        echo ""
        echo "Commands:"
        echo "  start       - Start the full 5G lab environment"
        echo "  stop        - Stop and cleanup the lab"
        echo "  restart     - Stop and start the lab"
        echo "  iperf       - Start iperf traffic generation"
        echo "  stop-iperf  - Stop iperf traffic"
        echo "  status      - Show lab status"
        exit 1
        ;;
esac
