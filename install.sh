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

print_status "Detectando método de instalación de Python..."

# Función para instalar paquetes Python
install_python_packages() {
    local packages="$1"
    local description="$2"
    
    # Método 1: Intentar pip3 normal
    if pip3 install -q $packages 2>/dev/null; then
        print_success "$description instalado con pip3"
        return 0
    fi
    
    # Método 2: Si falla, intentar con --break-system-packages
    print_warning "pip3 normal falló, intentando con --break-system-packages..."
    if pip3 install -q --break-system-packages $packages 2>/dev/null; then
        print_success "$description instalado con --break-system-packages"
        return 0
    fi
    
    # Método 3: Intentar con apt (paquetes del sistema)
    print_warning "pip3 falló, intentando con apt..."
    local apt_packages=""
    case "$packages" in
        *scapy*) apt_packages="python3-scapy";;
        *flask*) apt_packages="python3-flask python3-psutil python3-requests";;
        *scikit-learn*) apt_packages="python3-sklearn python3-numpy python3-pandas";;
    esac
    
    if [[ -n "$apt_packages" ]] && apt install -y $apt_packages > /dev/null 2>&1; then
        print_success "$description instalado con apt"
        return 0
    fi
    
    # Método 4: Crear venv si todo falla
    print_warning "Todos los métodos fallaron, creando entorno virtual..."
    if [[ ! -d "/opt/spooky-venv" ]]; then
        python3 -m venv /opt/spooky-venv
        print_status "Entorno virtual creado en /opt/spooky-venv"
    fi
    
    if source /opt/spooky-venv/bin/activate && pip install -q $packages; then
        print_success "$description instalado en entorno virtual"
        # Crear script wrapper
        cat > /usr/local/bin/spooky << 'EOF'
#!/bin/bash
source /opt/spooky-venv/bin/activate
exec python3 "$@"
EOF
        chmod +x /usr/local/bin/spooky
        print_status "Script wrapper creado: use 'sudo spooky spooky.py' en lugar de 'sudo python3 spooky.py'"
        return 0
    fi
    
    print_error "No se pudo instalar $description"
    return 1
}

print_status "Instalando dependencias básicas de Python..."
install_python_packages "scapy" "Scapy"

print_status "Instalando dependencias avanzadas de Python..."
install_python_packages "flask psutil requests" "Dependencias avanzadas"

print_status "Instalando dependencias opcionales para análisis ML..."
install_python_packages "scikit-learn numpy pandas" "Dependencias ML" || print_warning "Dependencias ML no instaladas (opcional)"

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

# Verificar si se creó entorno virtual
if [[ -d "/opt/spooky-venv" ]]; then
    echo "🔧 Se creó un entorno virtual debido a externally-managed-environment"
    echo "   Opciones para ejecutar Spooky:"
    echo "   • Opción 1 (Recomendada): sudo spooky spooky.py --help"
    echo "   • Opción 2: source /opt/spooky-venv/bin/activate && sudo python3 spooky.py"
    echo "   • Opción 3: sudo /opt/spooky-venv/bin/python3 spooky.py"
    echo
else
    echo "🎯 Próximos pasos:"
    echo "   1. sudo python3 spooky.py --help"
    echo "   2. sudo python3 spooky.py --profile corporate"
    echo "   3. Acceder al dashboard: http://localhost:5000"
fi

echo
echo "📋 Ejemplos de uso:"
if [[ -d "/opt/spooky-venv" ]]; then
    echo "   • Auditoria básica:"
    echo "     sudo spooky spooky.py --profile corporate --web-dashboard"
    echo
    echo "   • Red Team completo:"
    echo "     sudo spooky spooky.py --profile red_team --ssl-strip --stealth"
    echo
    echo "   • Solo monitoreo:"
    echo "     sudo spooky spooky.py --only-sniff --web-dashboard --ml-analysis"
else
    echo "   • Auditoria básica:"
    echo "     sudo python3 spooky.py --profile corporate --web-dashboard"
    echo
    echo "   • Red Team completo:"
    echo "     sudo python3 spooky.py --profile red_team --ssl-strip --stealth"
    echo
    echo "   • Solo monitoreo:"
    echo "     sudo python3 spooky.py --only-sniff --web-dashboard --ml-analysis"
fi

echo
echo "💡 Solución manual para externally-managed-environment:"
echo "   Si encuentras errores de 'externally-managed-environment':"
echo "   1. sudo rm /usr/lib/python*/EXTERNALLY-MANAGED"
echo "   2. O usa: pip install --break-system-packages <paquete>"
echo "   3. O crea venv: python3 -m venv spooky-env && source spooky-env/bin/activate"
echo

print_success "¡Spooky v2.0 Enhanced está listo para usar!"