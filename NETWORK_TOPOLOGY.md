# 5G Network Topology

## Overview

This document describes the current 5G SA (Standalone) network topology deployed using ContainerLab with Open5GS core and UERANSIM RAN simulator.

## High-Level Architecture

```mermaid
flowchart TB
    subgraph Internet
        WWW[Internet/8.8.8.8]
    end

    subgraph Core[5G Core - Open5GS]
        subgraph SBI[Service Based Interface - br-sbi]
            NRF[NRF<br/>10.254.1.4]
            SCP[SCP<br/>10.254.1.7]
            AUSF[AUSF<br/>10.254.1.2]
            UDM[UDM<br/>10.254.1.9]
            UDR[UDR<br/>10.254.1.10]
            PCF[PCF<br/>10.254.1.6]
            NSSF[NSSF<br/>10.254.1.5]
            BSF[BSF<br/>10.254.1.3]
            MongoDB[(MongoDB<br/>10.254.1.100)]
        end
        
        AMF[AMF<br/>10.100.1.1]
        SMF[SMF<br/>10.100.1.2]
        UPF[UPF<br/>10.100.1.3]
    end

    subgraph RAN[5G RAN - UERANSIM]
        GNB1[gNB1<br/>10.100.1.4<br/>NCI: 0x01]
        GNB2[gNB2<br/>10.100.1.5<br/>NCI: 0x02]
        GNB3[gNB3<br/>10.100.1.6<br/>NCI: 0x03]
    end

    subgraph UEs[User Equipment]
        UE1[UE1<br/>IMSI:...001]
        UE2[UE2<br/>IMSI:...002]
        UE3[UE3<br/>IMSI:...003]
        UE4[UE4<br/>IMSI:...004]
        UE5[UE5<br/>IMSI:...005]
        UE6[UE6<br/>IMSI:...006]
    end

    WWW <--> UPF
    UPF <-->|N3/N4| AMF
    UPF <-->|N4| SMF
    AMF <-->|N2| GNB1
    AMF <-->|N2| GNB2
    AMF <-->|N2| GNB3
    
    GNB1 <-->|NR-Uu| UE1
    GNB1 <-->|NR-Uu| UE2
    GNB2 <-->|NR-Uu| UE3
    GNB2 <-->|NR-Uu| UE4
    GNB3 <-->|NR-Uu| UE5
    GNB3 <-->|NR-Uu| UE6
```

## RAN Topology Detail

```mermaid
flowchart LR
    subgraph AMFBox[AMF - 10.100.1.1]
        AMF((AMF))
    end

    subgraph GNB1Box[gNB1 - Cell 0x01]
        GNB1((gNB1<br/>10.100.1.4))
    end
    
    subgraph GNB2Box[gNB2 - Cell 0x02]
        GNB2((gNB2<br/>10.100.1.5))
    end
    
    subgraph GNB3Box[gNB3 - Cell 0x03]
        GNB3((gNB3<br/>10.100.1.6))
    end

    subgraph UEGroup1[UEs on gNB1]
        UE1[UE1<br/>172.45.1.x]
        UE2[UE2<br/>172.45.1.x]
    end

    subgraph UEGroup2[UEs on gNB2]
        UE3[UE3<br/>172.45.1.x]
        UE4[UE4<br/>172.45.1.x]
    end

    subgraph UEGroup3[UEs on gNB3]
        UE5[UE5<br/>172.45.1.x]
        UE6[UE6<br/>172.45.1.x]
    end

    AMF ---|N2/SCTP:38412| GNB1
    AMF ---|N2/SCTP:38412| GNB2
    AMF ---|N2/SCTP:38412| GNB3
    
    GNB1 --- UE1
    GNB1 --- UE2
    GNB2 --- UE3
    GNB2 --- UE4
    GNB3 --- UE5
    GNB3 --- UE6
```

## Data Plane Flow

```mermaid
flowchart LR
    UE[UE<br/>uesimtun0] -->|GTP-U| GNB[gNodeB]
    GNB -->|N3/GTP-U| UPF[UPF<br/>ogstun]
    UPF -->|NAT| VIRBR[virbr0]
    VIRBR -->|Internet| WWW[8.8.8.8]
    
    style UE fill:#e1f5fe
    style GNB fill:#fff3e0
    style UPF fill:#e8f5e9
    style WWW fill:#fce4ec
```

## Control Plane Flow

```mermaid
sequenceDiagram
    participant UE
    participant gNB
    participant AMF
    participant AUSF
    participant UDM
    participant SMF
    participant UPF

    Note over UE,UPF: Registration Procedure
    UE->>gNB: RRC Connection
    gNB->>AMF: Initial UE Message (N2)
    AMF->>AUSF: Authentication Request
    AUSF->>UDM: Get Auth Data
    UDM-->>AUSF: Auth Vector
    AUSF-->>AMF: Auth Response
    AMF-->>UE: Auth Request/Response
    AMF->>UE: Registration Accept

    Note over UE,UPF: PDU Session Establishment
    UE->>AMF: PDU Session Request
    AMF->>SMF: Create SM Context
    SMF->>UPF: N4 Session Establishment
    UPF-->>SMF: N4 Response
    SMF-->>AMF: SM Context Created
    AMF-->>UE: PDU Session Accept
```

## Network Bridges

```mermaid
flowchart TB
    subgraph OVS[Open vSwitch Bridges]
        subgraph BRSBI[br-sbi]
            direction LR
            NRF1[NRF] --- SCP1[SCP] --- AMF1[AMF] --- SMF1[SMF]
            AUSF1[AUSF] --- UDM1[UDM] --- UDR1[UDR] --- PCF1[PCF]
        end
        
        subgraph BRN2N3N4[br-n2-n3-n4]
            direction LR
            AMF2[AMF<br/>N2] --- SMF2[SMF<br/>N4] --- UPF1[UPF<br/>N3/N4]
            GNB1A[gNB1] --- GNB2A[gNB2] --- GNB3A[gNB3]
        end
        
        subgraph BRNRUU[br-nr-uu]
            direction LR
            GNBS[gNB1/2/3] --- UES[UE1-6]
        end
    end
    
    subgraph LIBVIRT[libvirt]
        VIRBR0[virbr0<br/>NAT Gateway]
    end
    
    BRN2N3N4 --> VIRBR0
    VIRBR0 --> Internet((Internet))
```

## Network Components

### 5G Core Network Functions (Open5GS)

| NF | Container Name | SBI IP | Description |
|----|---------------|--------|-------------|
| NRF | clab-open5gs-5gc-nrf | 10.254.1.4 | Network Repository Function |
| SCP | clab-open5gs-5gc-scp | 10.254.1.7 | Service Communication Proxy |
| AMF | clab-open5gs-5gc-amf | 10.254.1.1 | Access and Mobility Management |
| SMF | clab-open5gs-5gc-smf | 10.254.1.8 | Session Management Function |
| UPF | clab-open5gs-5gc-upf | 10.100.1.3 | User Plane Function |
| AUSF | clab-open5gs-5gc-ausf | 10.254.1.2 | Authentication Server Function |
| UDM | clab-open5gs-5gc-udm | 10.254.1.9 | Unified Data Management |
| UDR | clab-open5gs-5gc-udr | 10.254.1.10 | Unified Data Repository |
| PCF | clab-open5gs-5gc-pcf | 10.254.1.6 | Policy Control Function |
| NSSF | clab-open5gs-5gc-nssf | 10.254.1.5 | Network Slice Selection Function |
| BSF | clab-open5gs-5gc-bsf | 10.254.1.3 | Binding Support Function |
| MongoDB | clab-open5gs-5gc-mongodb | 10.254.1.100 | Subscriber Database |
| WebUI | clab-open5gs-5gc-webui | 10.254.1.200 | Management Interface |

### gNodeBs (UERANSIM)

| gNodeB | Container | NR Cell ID | N2/N3 IP | NR-Uu IP | Serving UEs |
|--------|-----------|------------|----------|----------|-------------|
| gNB1 | clab-ueransim-gnb | 0x000000001 | 10.100.1.4 | 10.1.1.10 | UE1, UE2 |
| gNB2 | clab-ueransim-gnb2 | 0x000000002 | 10.100.1.5 | 10.1.1.11 | UE3, UE4 |
| gNB3 | clab-ueransim-gnb3 | 0x000000003 | 10.100.1.6 | 10.1.1.12 | UE5, UE6 |

### User Equipment (UERANSIM)

| UE | Container | IMSI | NR-Uu IP | Serving gNB | PDU Session |
|----|-----------|------|----------|-------------|-------------|
| UE1 | clab-ueransim-ue1 | 001010000000001 | 10.1.1.21 | gNB1 | 172.45.1.x |
| UE2 | clab-ueransim-ue2 | 001010000000002 | 10.1.1.22 | gNB1 | 172.45.1.x |
| UE3 | clab-ueransim-ue3 | 001010000000003 | 10.1.1.23 | gNB2 | 172.45.1.x |
| UE4 | clab-ueransim-ue4 | 001010000000004 | 10.1.1.24 | gNB2 | 172.45.1.x |
| UE5 | clab-ueransim-ue5 | 001010000000005 | 10.1.1.25 | gNB3 | 172.45.1.x |
| UE6 | clab-ueransim-ue6 | 001010000000006 | 10.1.1.26 | gNB3 | 172.45.1.x |

## PLMN Configuration

| Parameter | Value |
|-----------|-------|
| MCC | 001 |
| MNC | 01 |
| TAC | 1 |
| S-NSSAI SST | 1 |
| APN/DNN | internet |

## Subscriber Security

| Parameter | Value |
|-----------|-------|
| K | 465B5CE8B199B49FAA5F0A2EE238A6BC |
| OPc | E8ED289DEBA952E4283B54E88E6183CA |
| AMF | 8000 |

## WebUI Access

- **URL**: http://34.34.219.137/
- **Username**: admin
- **Password**: 1423

## Useful Commands

```bash
# Check all containers
sudo docker ps

# View gNB logs
sudo docker exec clab-ueransim-gnb cat /var/log/gnb.log

# View UE logs  
sudo docker exec clab-ueransim-ue1 cat /var/log/ue.log

# Check UE PDU session
sudo docker exec clab-ueransim-ue1 ip addr show uesimtun0

# Test connectivity from UE
sudo docker exec clab-ueransim-ue1 ping -I uesimtun0 8.8.8.8

# Check AMF registered gNBs
sudo docker exec clab-open5gs-5gc-amf cat /var/log/open5gs/amf.log | grep "Number of gNBs"

# List subscribers
sudo docker exec clab-open5gs-5gc-mongodb mongosh --quiet --eval \
  'db.getSiblingDB("open5gs").subscribers.find({}, {imsi: 1})'
```

## Monitoring Stack

### Architecture

```mermaid
flowchart TB
    subgraph Monitoring[Monitoring Stack]
        Prometheus[Prometheus<br/>:9091]
        Grafana[Grafana<br/>:3000]
        cAdvisor[cAdvisor<br/>:8080]
        NodeExp[Node Exporter<br/>:9100]
        MetricsCol[Metrics Collector<br/>:9200]
        eBPFCol[eBPF Collector<br/>:9201]
    end

    subgraph Core[5G Core]
        AMF[AMF]
        SMF[SMF]
        UPF[UPF]
        NRF[NRF]
        Other[Other NFs...]
    end

    subgraph RAN[UERANSIM]
        GNBs[gNodeBs]
        UEs[UEs]
    end

    subgraph Host[Host System]
        Docker[Docker Engine]
        System[System Metrics]
    end

    Grafana --> Prometheus
    Prometheus --> cAdvisor
    Prometheus --> NodeExp
    Prometheus --> MetricsCol
    Prometheus --> eBPFCol
    Prometheus --> AMF
    Prometheus --> SMF
    Prometheus --> UPF
    Prometheus --> NRF
    Prometheus --> Other

    cAdvisor --> Docker
    NodeExp --> System
    MetricsCol --> GNBs
    MetricsCol --> UEs
    eBPFCol --> UPF
    eBPFCol --> UEs
```

### Monitoring Components

| Component | Container | Port | Description |
|-----------|-----------|------|-------------|
| Prometheus | prometheus | 9091 | Time-series metrics database |
| Grafana | grafana | 3000 | Visualization dashboards |
| cAdvisor | cadvisor | 8080 | Container resource metrics |
| Node Exporter | node-exporter | 9100 | Host system metrics |
| Metrics Collector | metrics-collector | 9200 | 5G session & container metrics |
| eBPF Collector | ebpf-collector | 9201 | Per-UE traffic statistics |

### Data Flow

```mermaid
flowchart LR
    subgraph DataSources[Data Sources]
        UPF[UPF ogstun]
        UEtun[UE uesimtun0]
        Conntrack[conntrack]
        MongoDB[(MongoDB)]
    end

    subgraph Collectors[Collectors]
        eBPF[eBPF Collector]
        Metrics[Metrics Collector]
    end

    subgraph Storage[Storage & Display]
        Prom[Prometheus]
        Graf[Grafana]
    end

    UPF -->|/proc/net/dev| eBPF
    UEtun -->|/proc/net/dev| eBPF
    Conntrack -->|destinations| eBPF
    MongoDB -->|session info| eBPF
    MongoDB -->|subscribers| Metrics

    eBPF -->|ue_* metrics| Prom
    Metrics -->|gnb_*, ue_* metrics| Prom
    Prom --> Graf
```

### Grafana Dashboards

| Dashboard | File | Description |
|-----------|------|-------------|
| 5G Network Overview | `5g-network-overview.json` | System-wide view: CPU, memory, container stats, total traffic |
| UE Traffic Analytics | `ue-traffic-analytics.json` | Per-UE metrics: traffic, sessions, destinations, gNB breakdown |

### Key Metrics

#### Per-UE Metrics (eBPF Collector)

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `ue_bytes_in` | counter | ue_ip, imsi, gnb | Downlink bytes |
| `ue_bytes_out` | counter | ue_ip, imsi, gnb | Uplink bytes |
| `ue_packets_in` | counter | ue_ip, imsi, gnb | Downlink packets |
| `ue_packets_out` | counter | ue_ip, imsi, gnb | Uplink packets |
| `ue_session_duration_seconds` | gauge | ue_ip, imsi | Session duration |
| `ue_destination_connections` | gauge | ue_ip, dest_ip, dest_name, port, protocol | Connections per destination |

#### Container Metrics (cAdvisor)

| Metric | Description |
|--------|-------------|
| `container_cpu_usage_seconds_total` | CPU usage per container |
| `container_memory_usage_bytes` | Memory usage per container |
| `container_network_receive_bytes_total` | Network RX bytes |
| `container_network_transmit_bytes_total` | Network TX bytes |

#### Host Metrics (Node Exporter)

| Metric | Description |
|--------|-------------|
| `node_cpu_seconds_total` | Host CPU usage |
| `node_memory_MemTotal_bytes` | Total host memory |
| `node_network_receive_bytes_total` | Host network RX |
| `node_network_transmit_bytes_total` | Host network TX |

### Prometheus Scrape Targets

| Job Name | Target | Interval |
|----------|--------|----------|
| prometheus | localhost:9090 | 15s |
| node-exporter | localhost:9100 | 15s |
| cadvisor | localhost:8080 | 15s |
| metrics-collector | localhost:9200 | 15s |
| ebpf-collector | localhost:9201 | 5s |
| open5gs-amf | 10.254.1.1:9090 | 15s |
| open5gs-smf | 10.254.1.8:9090 | 15s |
| open5gs-upf | 10.100.1.3:9090 | 15s |
| open5gs-pcf | 10.254.1.6:9091 | 15s |
| open5gs-nrf | 10.254.1.4:9090 | 15s |
| open5gs-ausf | 10.254.1.2:9090 | 15s |
| open5gs-udm | 10.254.1.9:9090 | 15s |
| open5gs-udr | 10.254.1.10:9090 | 15s |
| open5gs-bsf | 10.254.1.3:9090 | 15s |
| open5gs-nssf | 10.254.1.5:9090 | 15s |
| open5gs-scp | 10.254.1.7:9090 | 15s |

### Monitoring Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Grafana | http://34.34.219.137/grafana | admin / admin |
| Prometheus | http://34.34.219.137/prometheus | - |

### Monitoring Commands

```bash
# Start monitoring stack
cd monitoring && sudo docker-compose up -d

# Stop monitoring stack
cd monitoring && sudo docker-compose down

# View collector logs
sudo docker logs -f ebpf-collector
sudo docker logs -f metrics-collector

# Check Prometheus targets
curl -s http://localhost:9091/prometheus/api/v1/targets | jq '.data.activeTargets[] | {job: .labels.job, health: .health}'

# Query UE traffic metrics
curl -s http://localhost:9201/metrics | grep "ue_bytes"

# Query destination metrics
curl -s http://localhost:9201/metrics | grep "ue_destination"
```

## File Locations

| File | Path |
|------|------|
| Open5GS Topology | `containerlab/5g-sa_open5gs_ueransim/topologies/open5gs-5gc.yaml` |
| UERANSIM Topology | `containerlab/5g-sa_open5gs_ueransim/topologies/ueransim.yaml` |
| gNB Configs | `containerlab/5g-sa_open5gs_ueransim/conf/ueransim/gnb*.yaml` |
| UE Configs | `containerlab/5g-sa_open5gs_ueransim/conf/ueransim/ue*.yaml` |
| Open5GS Configs | `containerlab/5g-sa_open5gs_ueransim/conf/open5gs/*.yaml` |
| Monitoring Compose | `monitoring/docker-compose.yml` |
| Prometheus Config | `monitoring/prometheus/prometheus.yml` |
| Grafana Dashboards | `monitoring/grafana/provisioning/dashboards/*.json` |
| eBPF Collector | `monitoring/collectors/ebpf_collector.py` |
| Metrics Collector | `monitoring/collectors/metrics_collector.py` |