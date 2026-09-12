#!/usr/bin/env python3
"""Launcher for KeenGuard."""
import os
import sys
import logging

# Suppress Scapy's raw libpcap loading warning on Windows if Npcap is not installed
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from keenguard.main import main

if __name__ == "__main__":
    main()
