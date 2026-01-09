#!/bin/bash
#
# 5G Network Monitoring Stack Deployment Script
# Deploys Prometheus, Grafana, cAdvisor, Node Exporter, and custom metrics collector
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║           5G Network Monitoring Dashboard                    ║"
    echo "║           Prometheus + Grafana + cAdvisor                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running or you don't have permission."
        log_info "Try running with sudo or add your user to the docker group."
        exit 1
    fi
    
    log_success "Docker is available"
}

check_docker_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
    else
        log_error "Docker Compose is not installed."
        exit 1
    fi
    log_success "Docker Compose is available ($COMPOSE_CMD)"
}

create_networks() {
    log_info "Checking Docker networks..."
    
    # The monitoring stack needs access to the 5G network containers
    # These networks are created by containerlab, so we just check they exist
    if docker network inspect br-sbi &> /dev/null; then
        log_success "Network br-sbi exists"
    else
        log_warn "Network br-sbi not found - Open5GS metrics may not be accessible"
    fi
    
    if docker network inspect br-n2-n3-n4 &> /dev/null; then
        log_success "Network br-n2-n3-n4 exists"
    else
        log_warn "Network br-n2-n3-n4 not found - UPF metrics may not be accessible"
    fi
}

deploy_stack() {
    log_info "Deploying monitoring stack..."
    
    # Build custom metrics collector
    log_info "Building custom metrics collector..."
    $COMPOSE_CMD build metrics-collector
    
    # Start all services
    log_info "Starting services..."
    $COMPOSE_CMD up -d
    
    log_success "Monitoring stack deployed successfully!"
}

stop_stack() {
    log_info "Stopping monitoring stack..."
    $COMPOSE_CMD down
    log_success "Monitoring stack stopped"
}

status() {
    log_info "Monitoring stack status:"
    $COMPOSE_CMD ps
}

print_access_info() {
    # Get host IP
    HOST_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    ACCESS INFORMATION                        ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}  Grafana:      ${BLUE}http://${HOST_IP}:3000${NC}                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Username:     admin                                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Password:     admin                                        ${GREEN}║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║${NC}  Prometheus:   ${BLUE}http://${HOST_IP}:9091${NC}                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  cAdvisor:     ${BLUE}http://${HOST_IP}:8080${NC}                        ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Node Exporter: ${BLUE}http://${HOST_IP}:9100/metrics${NC}              ${GREEN}║${NC}"
    echo -e "${GREEN}║${NC}  Metrics Collector: ${BLUE}http://${HOST_IP}:9200/metrics${NC}          ${GREEN}║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

logs() {
    $COMPOSE_CMD logs -f "$@"
}

usage() {
    echo "Usage: $0 {start|stop|restart|status|logs}"
    echo ""
    echo "Commands:"
    echo "  start    - Deploy and start the monitoring stack"
    echo "  stop     - Stop and remove the monitoring stack"
    echo "  restart  - Restart the monitoring stack"
    echo "  status   - Show status of monitoring services"
    echo "  logs     - Show logs (optional: service name)"
    echo ""
}

# Main
case "${1:-start}" in
    start)
        print_banner
        check_docker
        check_docker_compose
        create_networks
        deploy_stack
        print_access_info
        ;;
    stop)
        check_docker
        check_docker_compose
        stop_stack
        ;;
    restart)
        check_docker
        check_docker_compose
        stop_stack
        deploy_stack
        print_access_info
        ;;
    status)
        check_docker
        check_docker_compose
        status
        ;;
    logs)
        check_docker
        check_docker_compose
        shift
        logs "$@"
        ;;
    *)
        usage
        exit 1
        ;;
esac
