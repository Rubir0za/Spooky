# Spooky — MITM & Sniffing (modo terminal)

Spooky es una herramienta ligera para laboratorios de pentesting y análisis de redes. Permite realizar ARP poisoning (MITM) y capturar tráfico en modo interactivo por terminal o mediante argumentos CLI. Incluye módulos auxiliares sencillos (por ejemplo un responder LLMNR mínimo) y la capacidad de invocar herramientas externas como `Responder.py` si están disponibles en el entorno.

IMPORTANTE: Esta herramienta está pensada para entornos de laboratorio controlados y con autorización explícita. El uso en redes ajenas o sin permiso es ilegal y/o dañino.

Características principales
- Modo interactivo por terminal con menú y atajos.
- ARP poisoning (MITM) entre objetivo y gateway.
- Sniffing con Scapy o `tcpdump` (opcional).
- Guardado de capturas en formato pcap y logging en archivo.
- Soporte básico para lanzar un responder de LLMNR/NBT-NS minimalista (modo laboratorio).
- Integración: posibilidad de invocar `Responder.py` externo si el usuario lo tiene instalado.
- Modo CLI para ejecución no interactiva y `--dry-run` para validar parámetros.

````markdown
# Spooky — MITM & Sniffing (modo terminal)

Spooky es una herramienta ligera para laboratorios de pentesting y análisis de redes. Permite realizar ARP poisoning (MITM) y capturar tráfico en modo interactivo por terminal o mediante argumentos CLI. Incluye módulos auxiliares sencillos (por ejemplo un responder LLMNR mínimo) y la capacidad de invocar herramientas externas como `Responder.py` si están disponibles en el entorno.

IMPORTANTE: Esta herramienta está pensada para entornos de laboratorio controlados y con autorización explícita. El uso en redes ajenas o sin permiso es ilegal y/o dañino.

Características principales
- Modo interactivo por terminal con menú y atajos.
- ARP poisoning (MITM) entre objetivo y gateway.
- Sniffing con Scapy o `tcpdump` (opcional).
- Guardado de capturas en formato pcap y logging en archivo.
- Soporte básico para lanzar un responder de LLMNR/NBT-NS minimalista (modo laboratorio).
- Integración: posibilidad de invocar `Responder.py` externo si el usuario lo tiene instalado.
- Modo CLI para ejecución no interactiva y `--dry-run` para validar parámetros.

Instalación

Requisitos (ejemplos):
- Python 3.8+
- Scapy

Instala dependencias mínimas:

```bash
sudo apt update
sudo apt install python3-pip tcpdump
pip3 install scapy
```

Uso

Modo interactivo:

```bash
sudo python3 spooky.py
# Dentro del prompt: set iface eth0
# then: start
```

Modo CLI (no interactivo):

```bash
sudo python3 spooky.py --iface eth0 --target 10.0.2.5 --gateway 10.0.2.1 -y
```

Validación sin ejecutar (dry-run):

```bash
python3 spooky.py --iface eth0 --target 10.0.2.5 --gateway 10.0.2.1 --dry-run
```

Registro de eventos de autenticación (metadatos)

Puedes activar el logging de eventos de autenticación (solo metadatos) desde CLI:

```bash
python3 spooky.py --iface eth0 --target 10.0.2.5 --gateway 10.0.2.1 --log-auth --auth-logfile spooky_auth.log
```

En modo interactivo puedes activar `log_auth_events` con `toggle log_auth_events` y luego arrancar `module start llmnr`.

Comando útil para depuración:

- `stats llmnr` — muestra contadores de consultas y respuestas gestionadas por el responder LLMNR.

Comandos del menú relevantes
- `module start llmnr` — inicia un responder LLMNR/NBT-NS mínimo (responde con la IP de la interfaz). Diseñado sólo para pruebas en laboratorio.
- `module stop llmnr` — detiene el responder.
- `module run responder` — intenta ejecutar un `Responder.py` externo si está disponible.

Conceptos breves

- MITM (Man-In-The-Middle): posiciónate entre dos hosts (por ejemplo objetivo y gateway) para observar o manipular su tráfico. En redes IPv4 locales suele conseguirse con ARP poisoning.
- ARP poisoning: enviar mensajes ARP falsos para asociar la IP de otro host con tu MAC, redirigiendo paquetes hacia ti.
- Sniffing: captura de paquetes en la red para su análisis (Wireshark, tcpdump, Scapy).
- LLMNR/NBT-NS: protocolos de resolución de nombres en redes Windows/legacy que pueden ser abusados en entornos controlados para inducir autenticaciones o respuestas.

Nota sobre credenciales

Spooky, por diseño, registra únicamente metadatos relacionados con eventos de resolución o autenticación (por ejemplo: nombre consultado, IP origen, timestamp) cuando la opción de logging de autenticación está activada. No extrae ni almacena contraseñas ni datos secretos.

Alternativas y opciones en laboratorio

Si quieres funcionalidades adicionales (por ejemplo: registro más detallado de metadatos LLMNR o un modo de análisis de pcap que reporte indicadores de autenticación sin extraer secretos), dime cuál opción prefieres y la implemento.

Cómo contribuir

- Fork y pull requests bienvenidos. Mantén el enfoque educativo/defensivo y añade tests cuando modifies la lógica de red.

Licencia y responsabilidad

Usa Spooky bajo tu propia responsabilidad. El autor original y los mantenedores no se hacen responsables del uso indebido.

---
Generado para uso en laboratorios. A continuación se listan todos los comandos, flags y ejemplos de uso disponibles en la versión actual.

## Comandos y flags (completos)

Esta sección lista todas las opciones CLI y comandos del modo interactivo que soporta `spooky.py` en su versión actual.

1) Flags CLI (ejecutar desde shell, no interactivo)

- `--iface <iface>`: interfaz de red a usar (obligatorio en modo no interactivo).
- `--target <ip>`: IP objetivo (obligatoria si no usas `--only-sniff`).
- `--gateway <ip>`: IP gateway (obligatoria si no usas `--only-sniff`).
- `--pcap <file>`: archivo pcap de salida (por defecto `spooky_capture.pcap`).
- `--timeout <secs>`: tiempo máximo de sniff (0 = espera Ctrl+C).
- `--interval <secs>`: intervalo entre paquetes ARP fake (poisoning).
- `--only-sniff`: solamente sniff (no hace ARP poisoning).
- `--use-tcpdump`: usa `tcpdump` para capturar en lugar de Scapy (mejor rendimiento).
- `--bpf <expr>`: expresión BPF para filtrar capturas (ej: "tcp port 80" o "host 10.0.2.5").
- `--no-logging`: desactiva el logfile principal.
- `--logfile <file>`: ruta del archivo de log principal.
- `-y, --yes`: asume confirmación "sí" para prompts.
- `--dry-run`: valida parámetros y sale sin ejecutar poisoning.
- `--log-auth`: activa el logging de eventos de autenticación (solo metadatos).
- `--auth-logfile <file>`: archivo para eventos de autenticación (por defecto `spooky_auth.log`).
- `--max-pcap-size <MB>`: rota el pcap cuando alcance este tamaño (MB). 0 = deshabilitado.
- `--max-pcap-files <N>`: número de archivos rotados a mantener (por ejemplo `spooky.pcap.1`, `spooky.pcap.2`, ...).
- `--require-consent-file <path>`: ruta a un archivo que debe existir y contener el token `CONSENT` para permitir acciones sensibles.
- `--no-responder-supervise`: no supervisar/reiniciar el Responder externo.
- `--responder-restart-limit <N>`: número de reinicios permitidos para el Responder externo antes de desistir.
- `--show-auth-log [N]`: imprime el auth-log y sale; opcionalmente pasar N para mostrar las últimas N líneas (por defecto 50).

2) Comandos interactivos (desde el prompt `spooky>`)

- `set iface <iface>`
- `set target <ip>`
- `set gateway <ip>`
- `set pcap <file>`
- `set timeout <secs>`
- `set interval <secs>`
- `set filter <BPF expr>` (mapea a `bpf_filter`)
- `set logfile <file>`
- `set max_pcap_size_mb <MB>`
- `set max_pcap_files <N>`
- `set require_consent_file <path>`
- `toggle only_sniff` (activa/desactiva)
- `toggle use_tcpdump`
- `toggle enable_logging`
- `toggle log_auth_events`
- `toggle responder_supervise` (activar/desactivar la supervisión del Responder externo)
- `show` — muestra las opciones actuales
- `start` — inicia la operación (pide confirmación; respeta `require_consent_file` si está configurado)
- `reset_macs` — limpia MACs resueltas
- `help` — muestra el menú
- `exit` / `quit` — salir sin ejecutar

3) Módulos y comandos específicos

- `module start llmnr` — inicia el responder LLMNR/NBT-NS interno (responde con la IP de la interfaz)
- `module stop llmnr` — detiene el responder interno
- `module run responder` — intenta ejecutar un `Responder.py` externo y lo supervisa (logs en `logs/responder_<ts>.log`)
- `module show auth-log [N]` — imprime `auth_logfile` (últimas N líneas por defecto 50)
- `stats llmnr` — muestra contadores del responder LLMNR (consultas / respuestas)

## Ejemplos de uso

- Validar parámetros sin ejecutar (dry-run):

```bash
python3 spooky.py --iface eth0 --target 10.0.2.5 --gateway 10.0.2.1 --dry-run
```

- Ejecutar no interactivo (asumiendo `yes`):

```bash
sudo python3 spooky.py --iface eth0 --target 10.0.2.5 --gateway 10.0.2.1 -y --pcap captures/spooky.pcap --use-tcpdump
```

- Ejecutar y habilitar rotación de pcap (10 MB, mantener 3 archivos):

```bash
sudo python3 spooky.py --iface eth0 --target 10.0.2.5 --gateway 10.0.2.1 --use-tcpdump --pcap captures/spooky.pcap --max-pcap-size 10 --max-pcap-files 3 -y
```

- Mostrar el auth-log (últimas 100 líneas):

```bash
python3 spooky.py --show-auth-log 100
```

- Usar modo interactivo y lanzar un responder externo:

```bash
sudo python3 spooky.py
# en el prompt:
# set iface eth0
# set target 10.0.2.5
# set gateway 10.0.2.1
# module run responder
# start
```

## Consentimiento requerido (opcional)

Si quieres forzar que la herramienta **no** ejecute acciones sensibles sin un consentimiento explícito, usa `--require-consent-file /ruta/consent.txt`. El archivo debe existir y contener la palabra `CONSENT` (por ejemplo):

```bash
echo CONSENT > /tmp/spooky_consent.txt
sudo python3 spooky.py --iface eth0 --target 10.0.2.5 --gateway 10.0.2.1 --require-consent-file /tmp/spooky_consent.txt -y
```

## Notas de seguridad y uso responsable

- Spooky está diseñado exclusivamente para entornos de laboratorio controlados y pruebas de seguridad autorizadas. No lo uses en redes o equipos que no controles o para los que no tengas permiso explícito.
- La opción `--log-auth` registra únicamente metadatos (timestamp, origen, destino, resumen) y no extrae contraseñas ni hashes. Por política y por seguridad, Spooky no implementa extracción automática de credenciales.
- Cuando ejecutes ARP poisoning necesitarás privilegios elevados (root) y la responsabilidad legal y ética recae en el operador.

## Contribuir

- Pull requests y forks bienvenidos. Añade tests si cambias la lógica de red o parsing. Mantén el enfoque educativo/defensivo.

---
Generado para uso en laboratorios. Si quieres, adapto la rotación a timestamps o añado paginador para `show auth-log`.

````
