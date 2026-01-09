# 5G Lab Quick Start Guide

## Current State Saved: 2026-01-09

This lab includes:
- **Open5GS 5G Core** (AMF, SMF, UPF, PCF, NRF, AUSF, UDM, UDR, BSF, NSSF, SCP)
- **UERANSIM** (3 gNBs, 6 UEs)
- **Monitoring Stack** (Prometheus, Grafana, cAdvisor, Node Exporter)
- **iperf** installed on all UEs for traffic generation

## Quick Commands

### Start the Lab (from scratch)
```bash
cd /home/hiida/containerlab-cellular
./restore-lab.sh start
```

### Check Status
```bash
./restore-lab.sh status
```

### Start iperf Traffic Test
```bash
./restore-lab.sh iperf
```

### Stop iperf
```bash
./restore-lab.sh stop-iperf
```

### Stop the Lab
```bash
./restore-lab.sh stop
```

## Access URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://34.34.219.137/grafana | admin / admin |
| Prometheus | http://34.34.219.137/prometheus | - |
| Open5GS WebUI | http://34.34.219.137 | admin / 1423 |

## Network Configuration

| Network | Subnet | Purpose |
|---------|--------|---------|
| SBI | 10.254.1.0/24 | 5G Core SBI interfaces |
| N2/N3/N4 | 10.100.1.0/24 | RAN-Core interfaces |
| UE Pool | 172.45.0.0/16 | UE IP addresses |

## Container Images Saved

The following images have iperf pre-installed:
- `ueransim-ue1-saved:latest` through `ueransim-ue6-saved:latest`
- `ueransim-gnb-saved:latest`, `ueransim-gnb2-saved:latest`, `ueransim-gnb3-saved:latest`

## Monitoring Dashboard

The Grafana dashboard "5G Network Overview" shows:
1. **5G Core NF Status** - AMF, SMF, UPF, PCF status
2. **RAN & UE Status** - Connected gNBs, Registered UEs, PDU Sessions
3. **User Traffic** - Downlink/Uplink bytes, traffic rates
4. **Container Resources** - CPU and memory usage
5. **Host System** - CPU, memory, disk usage

## Traffic Generation

### Using iperf (high throughput)
```bash
# Start iperf server on host
iperf -s -p 5001 &

# Start iperf clients on UEs
for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
  sudo docker exec -d clab-ueransim-${ue} iperf -c 10.184.0.2 -p 5001 -t 60
done
```

### Using ping (low throughput)
```bash
for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
  sudo docker exec -d clab-ueransim-${ue} ping -I uesimtun0 8.8.8.8
done
```

## Troubleshooting

### UEs not registering
```bash
# Restart gNBs first
for gnb in gnb gnb2 gnb3; do
  sudo docker exec clab-ueransim-${gnb} pkill -9 nr-gnb
  sudo docker exec -d clab-ueransim-${gnb} bash -c "cd /UERANSIM && ./build/nr-gnb -c /gnb.yaml"
done
sleep 5

# Then restart UEs
for ue in ue1 ue2 ue3 ue4 ue5 ue6; do
  sudo docker exec clab-ueransim-${ue} pkill -9 nr-ue
  sudo docker exec -d clab-ueransim-${ue} bash -c "cd /UERANSIM && ./build/nr-ue -c /ue.yaml"
done
```

### Prometheus can't reach NFs
```bash
# Add IPs to bridges
sudo ip addr add 10.254.1.254/24 dev br-sbi
sudo ip addr add 10.100.1.254/24 dev br-n2-n3-n4
```

### Check logs
```bash
# AMF logs
sudo docker exec clab-open5gs-5gc-amf tail -50 /var/log/open5gs/amf.log

# UE logs
sudo docker exec clab-ueransim-ue1 tail -30 /var/log/ue.log

# gNB logs
sudo docker exec clab-ueransim-gnb tail -30 /var/log/gnb.log
```
