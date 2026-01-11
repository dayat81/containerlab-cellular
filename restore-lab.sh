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
    echo "[1/9] Deploying containerlab topology..."
    cd containerlab/5g-sa_open5gs_ueransim
    sudo containerlab deploy -t topologies/open5gs-5gc.yaml --reconfigure 2>/dev/null || \
    sudo containerlab deploy -t topologies/open5gs-5gc.yaml
    sudo containerlab deploy -t topologies/ueransim.yaml --reconfigure 2>/dev/null || \
    sudo containerlab deploy -t topologies/ueransim.yaml
    cd "$SCRIPT_DIR"
    
    echo ""
    echo "[2/9] Setting up network IPs for Prometheus access..."
    sudo ip addr add 10.254.1.254/24 dev br-sbi 2>/dev/null || true
    sudo ip addr add 10.100.1.254/24 dev br-n2-n3-n4 2>/dev/null || true
    sudo ip link set dev br-sbi up 2>/dev/null || true
    sudo ip link set dev br-n2-n3-n4 up 2>/dev/null || true
    
    # Step 2: Start MongoDB and add subscribers
    echo ""
    echo "[3/9] Starting MongoDB and adding subscribers..."
    sudo docker exec clab-open5gs-5gc-mongodb mkdir -p /data/db
    sudo docker exec clab-open5gs-5gc-mongodb pkill -9 mongod 2>/dev/null || true
    sleep 1
    sudo docker exec -d clab-open5gs-5gc-mongodb mongod --bind_ip_all
    sleep 3
    
    # Add subscribers to MongoDB
    cd containerlab/5g-sa_open5gs_ueransim
    for i in 1 2 3 4 5 6; do
        IMSI="00101000000000$i"
        sudo docker exec clab-open5gs-5gc-mongodb mongosh --quiet open5gs --eval "
            db.subscribers.replaceOne(
                {imsi: '$IMSI'},
                {
                    imsi: '$IMSI',
                    security: {
                        k: '465B5CE8B199B49FAA5F0A2EE238A6BC',
                        amf: '8000',
                        op: null,
                        opc: 'E8ED289DEBA952E4283B54E88E6183CA'
                    },
                    ambr: {
                        uplink: { value: 1, unit: 3 },
                        downlink: { value: 1, unit: 3 }
                    },
                    slice: [{
                        sst: 1,
                        default_indicator: true,
                        session: [{
                            name: 'internet',
                            type: 3,
                            pcc_rule: [],
                            ambr: {
                                uplink: { value: 1, unit: 3 },
                                downlink: { value: 1, unit: 3 }
                            },
                            qos: {
                                index: 9,
                                arp: {
                                    priority_level: 8,
                                    pre_emption_capability: 1,
                                    pre_emption_vulnerability: 1
                                }
                            }
                        }]
                    }],
                    access_restriction_data: 32,
                    subscriber_status: 0,
                    network_access_mode: 0,
                    subscribed_rau_tau_timer: 12,
                    __v: 0
                },
                {upsert: true}
            )
        " 2>/dev/null || true
    done
    cd "$SCRIPT_DIR"
    
    # Step 3: Copy Open5GS config files and start services
    echo ""
    echo "[4/9] Copying Open5GS configs and starting services..."
    cd containerlab/5g-sa_open5gs_ueransim
    for nf in nrf scp ausf udm udr pcf nssf bsf amf smf upf; do
        sudo docker cp conf/open5gs/${nf}.yaml clab-open5gs-5gc-$nf:/open5gs/install/etc/open5gs/${nf}.yaml 2>/dev/null || true
        sudo docker exec clab-open5gs-5gc-$nf pkill -9 open5gs 2>/dev/null || true
    done
    cd "$SCRIPT_DIR"
    sleep 2
    
    # Start Open5GS services in proper order
    for nf in nrf scp; do
        sudo docker exec -d clab-open5gs-5gc-$nf /open5gs/install/bin/open5gs-${nf}d
        sleep 1
    done
    sleep 3
    
    for nf in ausf udm udr pcf nssf bsf; do
        sudo docker exec -d clab-open5gs-5gc-$nf /open5gs/install/bin/open5gs-${nf}d
        sleep 0.3
    done
    sleep 2
    
    for nf in amf smf upf; do
        sudo docker exec -d clab-open5gs-5gc-$nf /open5gs/install/bin/open5gs-${nf}d
        sleep 1
    done
    sleep 3
    
    # Step 4: Start monitoring stack
    echo ""
    echo "[5/9] Starting monitoring stack (Prometheus + Grafana)..."
    cd monitoring
    sudo docker-compose up -d
    cd "$SCRIPT_DIR"
    
    echo ""
    echo "[6/9] Waiting for services to stabilize (10 seconds)..."
    sleep 10
    
    # Step 5: Copy gNB and UE config files
    echo ""
    echo "[7/9] Copying gNB and UE configuration files..."
    cd containerlab/5g-sa_open5gs_ueransim
    sudo docker cp conf/ueransim/gnb.yaml clab-ueransim-gnb:/UERANSIM/build/gnb.yaml 2>/dev/null || true
    sudo docker cp conf/ueransim/gnb2.yaml clab-ueransim-gnb2:/UERANSIM/build/gnb.yaml 2>/dev/null || true
    sudo docker cp conf/ueransim/gnb3.yaml clab-ueransim-gnb3:/UERANSIM/build/gnb.yaml 2>/dev/null || true
    
    for i in 1 2 3 4 5 6; do
        sudo docker cp conf/ueransim/ue${i}.yaml clab-ueransim-ue$i:/UERANSIM/build/ue.yaml 2>/dev/null || true
    done
    cd "$SCRIPT_DIR"
    
    # Step 6: Start gNBs
    echo ""
    echo "[8/9] Starting gNBs and UEs..."
    for gnb in gnb gnb2 gnb3; do
        sudo docker exec clab-ueransim-${gnb} pkill -9 nr-gnb 2>/dev/null || true
        sleep 0.3
        sudo docker exec -d clab-ueransim-${gnb} bash -c "cd /UERANSIM/build && ./nr-gnb -c gnb.yaml > /var/log/gnb.log 2>&1"
    done
    sleep 5
    
    # Step 7: Start UEs
    for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
        sudo docker exec clab-ueransim-${ue} pkill -9 nr-ue 2>/dev/null || true
        sudo docker exec clab-ueransim-${ue} pkill -9 ping 2>/dev/null || true
        sudo docker exec clab-ueransim-${ue} pkill -9 iperf 2>/dev/null || true
        sleep 0.3
        sudo docker exec -d clab-ueransim-${ue} bash -c "cd /UERANSIM/build && ./nr-ue -c ue.yaml > /var/log/ue.log 2>&1"
    done
    sleep 10
    
    # Step 8: Start background pings
    echo ""
    echo "[9/9] Starting background traffic (pings from all UEs)..."
    for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
        sudo docker exec -d clab-ueransim-${ue} ping -I uesimtun0 8.8.8.8 > /dev/null 2>&1 || true
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
