#!/bin/bash
# Spooky v2.0 - Script de Instalación Automática
# Instala todas las dependencias necesarias para Spooky Enhanced

set -e

echo "🕷️ Spooky v2.0 - Enhanced Edition Installation Script"
echo "=================================================="

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Verificar si se ejecuta como root
if [[ $EUID -ne 0 ]]; then
   print_error "Este script debe ejecutarse como root (sudo)"
   exit 1
fi

print_status "Actualizando repositorios del sistema..."
apt update -qq

print_status "Instalando dependencias del sistema..."
apt install -y python3 python3-pip tcpdump net-tools iproute2 > /dev/null 2>&1
print_success "Dependencias del sistema instaladas"

print_status "Instalando dependencias básicas de Python..."
pip3 install -q scapy
print_success "Scapy instalado"

print_status "Instalando dependencias avanzadas de Python..."
pip3 install -q flask psutil requests > /dev/null 2>&1
print_success "Dependencias avanzadas instaladas"

print_status "Instalando dependencias opcionales para análisis ML..."
pip3 install -q scikit-learn numpy pandas > /dev/null 2>&1 || print_warning "Dependencias ML no instaladas (opcional)"

print_status "Configurando permisos..."
# Permitir tcpdump sin sudo para usuarios específicos
if ! grep -q "^tcpdump:" /etc/group; then
    groupadd tcpdump 2>/dev/null || true
fi

# Dar permisos especiales a tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/bin/tcpdump 2>/dev/null || print_warning "No se pudieron establecer capabilities para tcpdump"

print_status "Creando directorios de trabajo..."
mkdir -p /var/log/spooky
mkdir -p /opt/spooky/reports
mkdir -p /opt/spooky/pcaps
chmod 755 /var/log/spooky /opt/spooky/reports /opt/spooky/pcaps

print_status "Verificando instalación..."
python3 -c "import scapy.all; print('Scapy OK')" 2>/dev/null && print_success "Scapy verificado"
python3 -c "import flask; print('Flask OK')" 2>/dev/null && print_success "Flask verificado" || print_warning "Flask no disponible"
python3 -c "import psutil; print('psutil OK')" 2>/dev/null && print_success "psutil verificado" || print_warning "psutil no disponible"

# Verificar que el archivo principal existe
if [[ ! -f "spooky.py" ]]; then
    print_warning "spooky.py no encontrado en el directorio actual"
    print_warning "Asegúrate de estar en el directorio correcto"
fi

print_success "¡Instalación completada!"
echo
echo "🎯 Próximos pasos:"
echo "   1. sudo python3 spooky.py --help"
echo "   2. sudo python3 spooky.py --profile corporate"
echo "   3. Acceder al dashboard: http://localhost:5000"
echo
echo "📋 Ejemplos de uso:"
echo "   • Auditoria básica:"
echo "     sudo python3 spooky.py --profile corporate --web-dashboard"
echo
echo "   • Red Team completo:"
echo "     sudo python3 spooky.py --profile red_team --ssl-strip --stealth"
echo
echo "   • Solo monitoreo:"
echo "     sudo python3 spooky.py --only-sniff --web-dashboard --ml-analysis"
echo
print_success "¡Spooky v2.0 Enhanced está listo para usar!"