import sqlite3
import hashlib
import os
import random
import string
import re
import datetime
import traceback
import subprocess
from datetime import datetime as dt, timedelta
from flask import Flask, jsonify, render_template, request, send_from_directory, abort
from scanner import WebScanner
from model_sim import TrafficSimulator

DB_FILE = 'sentinel.db'

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_code TEXT PRIMARY KEY,
            name TEXT,
            email TEXT UNIQUE,
            password_hash TEXT,
            otp TEXT,
            otp_expiry TEXT,
            status TEXT,
            created_at TEXT
        )
    ''')
    
    # Activity table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            user TEXT,
            action TEXT
        )
    ''')
    
    # Stats table (simple key-value metadata store)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_stats (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    # Seed default user if not exists
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_code = "123456"
        admin_pass_hash = hashlib.sha256(("admin123" + admin_code).encode('utf-8')).hexdigest()
        cursor.execute('''
            INSERT INTO users (user_code, name, email, password_hash, otp, otp_expiry, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (admin_code, "Agent Johnson", "johnson@sentinel.net", admin_pass_hash, "", "", "ACTIVE", dt.utcnow().isoformat() + "Z"))
        
        # Seed default activities
        default_activities = [
            ("05:12 PM", "Operator", "Executed traffic scan check"),
            ("02:18 PM", "System", "Firewall segment WAN optimized"),
            ("09:41 AM", "Operator", "Authorized session established")
        ]
        for time_str, user_val, action_val in default_activities:
            cursor.execute('''
                INSERT INTO activities (time, user, action)
                VALUES (?, ?, ?)
            ''', (time_str, user_val, action_val))
            
        # Seed visitor statistics (JSON stored in stats)
        visitor_stats = [120, 180, 140, 290, 310, 480, 390, 520, 580, 510, 720, 891]
        import json
        cursor.execute("INSERT OR REPLACE INTO system_stats (key, value) VALUES ('visitor_stats', ?)", (json.dumps(visitor_stats),))
        
    conn.commit()
    conn.close()

# Initialize Database Schema
init_db()

def scan_nearby_networks():
    networks = []
    
    # 1. Attempt Linux NMCLI scan
    try:
        if os.name != 'nt':
            result = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN", "dev", "wifi"], capture_output=True, text=True, errors='ignore')
            if result.returncode == 0 and result.stdout.strip():
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(':')
                    if len(parts) >= 5:
                        ssid = parts[0] or "Hidden SSID"
                        signal = parts[2] + "%"
                        security = parts[3] or "Open"
                        channel = parts[4]
                        
                        auth = "WPA2"
                        enc = "AES"
                        if "WPA3" in security:
                            auth = "WPA3"
                        elif "WPA1" in security or "WEP" in security:
                            auth = "WEP"
                        elif "802.1X" in security:
                            auth = "WPA2-Enterprise"
                        elif "Open" in security or not security:
                            auth = "Open"
                            enc = "None"
                            
                        networks.append({
                            "ssid": ssid,
                            "auth": auth,
                            "enc": enc,
                            "signal": signal,
                            "channel": channel,
                            "radio": "802.11ac",
                            "type": "Wireless"
                        })
    except Exception as ex:
        print("Linux nmcli WiFi scan skipped:", ex)

    # 2. Attempt Windows Netsh Scan
    if not networks and os.name == 'nt':
        try:
            result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, errors='ignore')
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                current_ssid = None
                current_auth = "Unknown"
                current_enc = "Unknown"
                current_signal = "80%"
                current_channel = "Auto"
                current_radio = "802.11ac"
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Match SSID lines (locale-agnostic checks)
                    ssid_match = re.match(r'^(?:SSID\s+\d+\s*:\s*|SSID\s+\d+\s*SSID\s*:\s*)(.*)$', line, re.IGNORECASE)
                    if not ssid_match:
                        # Fallback for non-English SSIDs
                        if line.startswith("SSID "):
                            parts = line.split(":", 1)
                            if len(parts) > 1:
                                name = parts[1].strip()
                                current_ssid = name if name else "Hidden SSID"
                    else:
                        if current_ssid:
                            networks.append({
                                "ssid": current_ssid,
                                "auth": current_auth,
                                "enc": current_enc,
                                "signal": current_signal,
                                "channel": current_channel,
                                "radio": current_radio,
                                "type": "Wireless"
                            })
                        name = ssid_match.group(1).strip()
                        current_ssid = name if name else "Hidden SSID"
                        current_auth = "Unknown"
                        current_enc = "Unknown"
                        current_signal = "85%"
                        current_channel = "6"
                        current_radio = "802.11ac"
                        
                    if "Authentication" in line or "Authentifizierung" in line or "Authentification" in line or "auth" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            current_auth = parts[1].strip()
                    elif "Encryption" in line or "Verschlüsselung" in line or "Chiffrement" in line or "enc" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            current_enc = parts[1].strip()
                    elif "Signal" in line or "signal" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            current_signal = parts[1].strip()
                    elif "Channel" in line or "Kanal" in line or "Canal" in line or "channel" in line.lower():
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            current_channel = parts[1].strip()
                    elif "Radio type" in line or "Funktyp" in line or "Type de radio" in line:
                        parts = line.split(":", 1)
                        if len(parts) > 1:
                            current_radio = parts[1].strip()
                            
                if current_ssid:
                    networks.append({
                        "ssid": current_ssid,
                        "auth": current_auth,
                        "enc": current_enc,
                        "signal": current_signal,
                        "channel": current_channel,
                        "radio": current_radio,
                        "type": "Wireless"
                    })
        except Exception as e:
            print("Windows netsh WiFi scan execution skipped:", e)
        
    # 3. Fallback to listing machine netcard interfaces
    if not networks:
        try:
            import psutil
            addrs = psutil.net_if_addrs()
            for name in addrs.keys():
                if "loopback" not in name.lower() and "localhost" not in name.lower():
                    networks.append({
                        "ssid": name,
                        "auth": "Wired/Virtual",
                        "enc": "Secure Link",
                        "signal": "100%",
                        "channel": "Wired",
                        "radio": "GbE Link",
                        "type": "Interface"
                    })
        except Exception as ex:
            print("System network card interfaces query skipped:", ex)
            
    # 4. Standard simulated networks list always present to populate wifi selection lists correctly
    simulated_nets = [
        {"ssid": "Wi-Fi (Automatic Selector)", "auth": "WPA3", "enc": "AES", "signal": "90%", "channel": "11", "radio": "802.11ax", "type": "Wireless"},
        {"ssid": "Sentinel_Secure_5G", "auth": "WPA3-Personal", "enc": "CCMP", "signal": "98%", "channel": "36", "radio": "802.11ax", "type": "Wireless"},
        {"ssid": "vm-26-asus (Nearby)", "auth": "WPA2-Personal", "enc": "CCMP", "signal": "75%", "channel": "6", "radio": "802.11ac", "type": "Wireless"},
        {"ssid": "CommunityFibre_Guest", "auth": "Open", "enc": "None", "signal": "65%", "channel": "1", "radio": "802.11n", "type": "Wireless"},
        {"ssid": "Office_Intel_LAN", "auth": "Wired/Virtual", "enc": "Secure Link", "signal": "100%", "channel": "Wired", "radio": "GbE Link", "type": "Interface"},
        {"ssid": "Malicious_Pineapple_AP", "auth": "Open", "enc": "None", "signal": "92%", "channel": "11", "radio": "802.11n", "type": "Wireless"},
        {"ssid": "BT-MXFJTQ", "auth": "WPA2-Personal", "enc": "CCMP", "signal": "80%", "channel": "6", "radio": "802.11ac", "type": "Wireless"}
    ]
    
    # Merge networks while avoiding duplicate SSIDs
    existing_ssids = {n['ssid'].lower() for n in networks}
    for sim in simulated_nets:
        if sim['ssid'].lower() not in existing_ssids:
            networks.append(sim)
            existing_ssids.add(sim['ssid'].lower())
            
    return networks

def get_network_details(interface_type=None):
    details = {
        "ipv4": "127.0.0.1",
        "gateway": "0.0.0.0",
        "dns": "8.8.8.8",
        "mac": "00:00:00:00:00:00"
    }
    
    # Attempt Windows IP config details mapping
    if os.name == 'nt':
        try:
            result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, errors='ignore')
            output = result.stdout
            sections = re.split(r'\n(?=[a-zA-Z0-9])', output)
            best_section = None
            
            for section in sections:
                if interface_type:
                    if interface_type.lower() == 'wifi':
                        if "wireless" not in section.lower() or "disconnected" in section.lower():
                            continue
                    elif interface_type.lower() == 'ethernet':
                        if "ethernet" not in section.lower() or "virtualbox" in section.lower() or "disconnected" in section.lower():
                            continue
                else:
                    if "disconnected" in section.lower():
                        continue
                
                if "IPv4 Address" in section or "IPv4-Adresse" in section:
                    best_section = section
                    if "Default Gateway" in section or "Standardgateway" in section:
                        break
            
            if not best_section and interface_type:
                for section in sections:
                    if interface_type.lower() == 'wifi' and "wireless" in section.lower():
                        best_section = section
                        break
                    elif interface_type.lower() == 'ethernet' and "ethernet" in section.lower():
                        best_section = section
                        break
                        
            if not best_section:
                for section in sections:
                    if "IPv4 Address" in section or "IPv4-Adresse" in section:
                        best_section = section
                        break
    
            if best_section:
                mac_match = re.search(r'(?:Physical Address|Physikalische Adresse|Adresse physique)[.\s]*:\s*([0-9A-Fa-f-]+)', best_section)
                ip_match = re.search(r'(?:IPv4 Address|IPv4-Adresse|Adresse IPv4)[.\s]*:\s*([0-9.]+)', best_section)
                gw_match = re.search(r'(?:Default Gateway|Standardgateway|Passerelle par défaut)[.\s]*:\s*([0-9.]+)', best_section)
                
                dns_servers = []
                dns_header = "DNS Servers"
                if "DNS-Server" in best_section:
                    dns_header = "DNS-Server"
                elif "Serveurs DNS" in best_section:
                    dns_header = "Serveurs DNS"
                    
                if dns_header in best_section:
                    block_text = best_section.split(dns_header)[1].split("NetBIOS")[0]
                    ips = re.findall(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', block_text)
                    if ips:
                        dns_servers = ips
                
                if mac_match: details["mac"] = mac_match.group(1).replace('-', ':').upper()
                if ip_match: details["ipv4"] = ip_match.group(1)
                if gw_match: details["gateway"] = gw_match.group(1)
                if dns_servers:
                    details["dns"] = dns_servers[0]
                elif gw_match:
                    details["dns"] = gw_match.group(1)
        except Exception as e:
            print("Error reading network details:", e)
            
    # Attempt Unix/macOS parsing fallback
    else:
        try:
            import socket
            hostname = socket.gethostname()
            ip_val = socket.gethostbyname(hostname)
            if not ip_val.startswith("127."):
                details["ipv4"] = ip_val
        except Exception:
            pass
            
    return details

app = Flask(__name__)

# Singletons initialization
simulator = TrafficSimulator()
scan_history = []

@app.after_request
def add_security_and_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    
    # Strip sensitive server version information tags
    response.headers.set('Server', 'Sentinel Security Core')
    response.headers.pop('X-Powered-By', None)
    
    # HTTP Security Headers injection
    response.headers.add('X-Content-Type-Options', 'nosniff')
    response.headers.add('X-Frame-Options', 'SAMEORIGIN')
    response.headers.add('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    response.headers.add('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; media-src 'self'; connect-src 'self'")
    return response

# Web Application Firewall (WAF) Input Parameter Scanner
@app.before_request
def inspect_requests_waf():
    from urllib.parse import unquote
    
    # 1. SQL Injection Regex Signatures
    sqli_pattern = re.compile(
        r"(\bUNION\b.*\bSELECT\b)|(\bSELECT\b.*\bFROM\b)|(\bINSERT\b.*\bINTO\b)|(\bDELETE\b.*\bFROM\b)|(\bDROP\b\s+\bTABLE\b)|(\bOR\b\s+['\"].+=['\x22\x27].+)|(';)",
        re.IGNORECASE
    )
    # 2. Cross-Site Scripting (XSS) Regex Signatures
    xss_pattern = re.compile(
        r"(<script\b[^>]*>)|(javascript:)|(onerror\s*=)|(onload\s*=)|(eval\s*\()|(<[^>]+on\w+\s*=)",
        re.IGNORECASE
    )
    # 3. Path Traversal & File Inclusions Signatures
    path_pattern = re.compile(r"(\dots/)|(\.\./)|(\.\.\\)|(/etc/passwd)|(boot\.ini)", re.IGNORECASE)
    
    blocked = False
    violation_type = ""
    malicious_payload = ""
    
    # Inspect Request URL query string
    if request.query_string:
        decoded_query = unquote(request.query_string.decode('utf-8', errors='ignore'))
        if sqli_pattern.search(decoded_query):
            blocked = True
            violation_type = "SQL Injection Payload"
            malicious_payload = decoded_query
        elif xss_pattern.search(decoded_query):
            blocked = True
            violation_type = "Cross-Site Scripting Script"
            malicious_payload = decoded_query
        elif path_pattern.search(decoded_query):
            blocked = True
            violation_type = "Directory Path Traversal"
            malicious_payload = decoded_query
            
    # Check all key-values in query arguments
    if not blocked and request.args:
        for k, v in request.args.items():
            decoded_v = unquote(v)
            if sqli_pattern.search(decoded_v):
                blocked = True
                violation_type = "SQL Injection Payload"
                malicious_payload = f"{k}={decoded_v}"
                break
            elif xss_pattern.search(decoded_v):
                blocked = True
                violation_type = "Cross-Site Scripting Script"
                malicious_payload = f"{k}={decoded_v}"
                break
            elif path_pattern.search(decoded_v):
                blocked = True
                violation_type = "Directory Path Traversal"
                malicious_payload = f"{k}={decoded_v}"
                break

    # Inspect JSON form payloads or raw payloads
    if not blocked:
        raw_body = ""
        if request.is_json:
            try:
                import json
                raw_body = json.dumps(request.get_json(silent=True) or {})
            except Exception:
                pass
        else:
            raw_body = request.get_data(as_text=True) or ""
            
        if raw_body:
            decoded_body = unquote(raw_body)
            if sqli_pattern.search(decoded_body):
                blocked = True
                violation_type = "SQL Injection Payload"
                malicious_payload = decoded_body[:120]
            elif xss_pattern.search(decoded_body):
                blocked = True
                violation_type = "Cross-Site Scripting Script"
                malicious_payload = decoded_body[:120]
            elif path_pattern.search(decoded_body):
                blocked = True
                violation_type = "Directory Path Traversal"
                malicious_payload = decoded_body[:120]
                
    if blocked:
        # Generate and insert simulated attack telemetry directly into live stream
        source_ip = request.remote_addr or "185.220.101.5"
        timestamp = dt.now()
        
        # Inject warning packet directly into Traffic Simulator instance
        incident_pkt = {
            "id": f"PKT-{random.randint(100000, 999999)}",
            "time": timestamp.strftime("%H:%M:%S"),
            "timestamp": timestamp.timestamp(),
            "src_ip": source_ip,
            "dest_ip": "10.0.0.12",
            "protocol": "HTTP",
            "length": len(malicious_payload),
            "threat": "SQL Injection" if "SQL" in violation_type else "DDoS Attack",
            "confidence": 0.9985,
            "severity": "Critical" if "SQL" in violation_type else "High",
            "info": f"WAF Intercepted: {violation_type} signature inside parameters."
        }
        
        # Insert alert directly into the singleton traffic simulator
        try:
            simulator.packets_history.append(incident_pkt)
            simulator.total_packets_checked += 1
            simulator.total_threats_detected += 1
            simulator.threat_counts["SQL Injection" if "SQL" in violation_type else "DDoS Attack"] += 1
            alert = simulator._create_alert_from_packet(incident_pkt)
            simulator.alerts_history.insert(0, alert)
        except Exception:
            pass
        
        # System status changes to alert dashboard
        print(f"[WAF SHIELD TRIGGERED] Blocked {violation_type} from IP {source_ip}")
        abort(403, description=f"Security Violation: {violation_type} signature detected and logged.")


@app.route('/')
def index():
    return render_template('dashboard.html')

# Secure Asset Serving wrapper routing
@app.route('/<path:filename>')
def serve_root_files(filename):
    # Strictly prevent directory traversal and block access to python source files, databases, or local configs
    normalized_path = os.path.normpath(filename)
    if normalized_path.startswith("..") or normalized_path.startswith("/") or normalized_path.startswith("\\"):
        abort(403, "Access Denied: Path Traversal forbidden.")
        
    restricted_extensions = ['.py', '.db', '.json', '.sqlite', '.log', '.git', '.env', '.bat', '.sh']
    _, ext = os.path.splitext(normalized_path.lower())
    if ext in restricted_extensions:
        abort(403, "Access Denied: Secure source configuration assets cannot be queried.")
        
    return send_from_directory('.', filename)

@app.route('/api/traffic', methods=['GET'])
def get_traffic():
    try:
        update_data = simulator.get_live_update()
        return jsonify(update_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_history():
    try:
        history = simulator.get_history()
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    try:
        alerts = simulator.get_alerts()
        return jsonify(alerts)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        stats = simulator.get_aggregated_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/model-performance', methods=['GET'])
def get_model_performance():
    try:
        perf = simulator.get_model_performance()
        return jsonify(perf)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/scan', methods=['POST'])
def run_scan():
    try:
        data = request.get_json() or {}
        url = data.get('url', '').strip()
        if not url:
            return jsonify({"error": "Please provide a valid website address."}), 400
            
        report = WebScanner.scan_website(url)
        if "error" in report:
            return jsonify(report), 400
            
        scan_history.insert(0, report)
        if len(scan_history) > 30:
            scan_history.pop()
            
        return jsonify(report)
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"Internal scan error: {str(e)}"}), 500

@app.route('/api/scan-history', methods=['GET'])
def get_scan_history():
    try:
        return jsonify(scan_history)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/networks', methods=['GET'])
def get_networks():
    try:
        return jsonify(scan_nearby_networks())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/network-details', methods=['GET'])
def get_details():
    try:
        interface_type = request.args.get('interface', '')
        ssid = request.args.get('ssid', '')
        auth = request.args.get('auth', '')
        enc = request.args.get('enc', '')
        
        connected_ssid = None
        try:
            res = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, errors='ignore')
            for line in res.stdout.split('\n'):
                if "SSID" in line and "BSSID" not in line:
                    connected_ssid = line.split(":")[1].strip()
                    break
        except Exception:
            pass
            
        is_connected = False
        if ssid and connected_ssid:
            if ssid.lower() == connected_ssid.lower():
                is_connected = True
                
        details = None
        
        if interface_type.lower() == 'wifi' and ssid and not is_connected:
            import hashlib
            h = hashlib.md5(ssid.encode('utf-8')).hexdigest()
            ip_third = (int(h[0:2], 16) % 250) + 1
            ip_fourth = (int(h[2:4], 16) % 250) + 2
            mac_p1 = h[4:6].upper()
            mac_p2 = h[6:8].upper()
            mac_p3 = h[8:10].upper()
            dns_provider = ["8.8.4.4", "1.1.1.1", "9.9.9.9", f"192.168.{ip_third}.1"]
            selected_dns = dns_provider[int(h[10:12], 16) % len(dns_provider)]
            
            details = {
                "ipv4": f"192.168.{ip_third}.{ip_fourth}",
                "gateway": f"192.168.{ip_third}.1",
                "dns": selected_dns,
                "mac": f"CC:47:40:{mac_p1}:{mac_p2}:{mac_p3}"
            }
        else:
            details = get_network_details(interface_type)
            
        profiles = {
            "Wi-Fi (Automatic Selector)": {
                "level": "Low (Safe)",
                "level_color": "var(--green)",
                "vulnerability": "None detected",
                "threats": "None active"
            },
            "Sentinel_Secure_5G": {
                "level": "Safe (WPA3)",
                "level_color": "var(--green)",
                "vulnerability": "None detected",
                "threats": "None active"
            },
            "vm-26-asus (Nearby)": {
                "level": "Low Risk",
                "level_color": "var(--green)",
                "vulnerability": "Legacy WPA2 protocol",
                "threats": "Brute force risk"
            },
            "CommunityFibre_Guest": {
                "level": "Medium Risk",
                "level_color": "var(--orange)",
                "vulnerability": "Unencrypted open network",
                "threats": "Sniffing, MitM risk"
            },
            "Office_Intel_LAN": {
                "level": "Safe (Wired)",
                "level_color": "var(--green)",
                "vulnerability": "None detected",
                "threats": "None active"
            },
            "Malicious_Pineapple_AP": {
                "level": "Critical Risk",
                "level_color": "var(--red)",
                "vulnerability": "Rogue Access Point (Evil Twin)",
                "threats": "Hijacking, credentials theft"
            },
            "BT-MXFJTQ": {
                "level": "Low Risk",
                "level_color": "var(--green)",
                "vulnerability": "Default pre-shared key",
                "threats": "Key cracking risk"
            }
        }
        
        profile = None
        target_ssid = ssid if ssid else (connected_ssid if connected_ssid else interface_type)
        
        if target_ssid:
            for key, val in profiles.items():
                if key.lower() in target_ssid.lower() or target_ssid.lower() in key.lower():
                    profile = val
                    break
                    
        if not profile:
            is_open = False
            if auth:
                if auth.lower() == 'open' or enc.lower() == 'none':
                    is_open = True
            if is_open:
                profile = {
                    "level": "High Risk",
                    "level_color": "var(--red)",
                    "vulnerability": "Unencrypted Open Connection",
                    "threats": "Traffic sniffing, MitM attacks"
                }
            elif interface_type.lower() == 'ethernet' or interface_type.lower() == 'interface':
                profile = {
                    "level": "Safe (Wired)",
                    "level_color": "var(--green)",
                    "vulnerability": "None detected",
                    "threats": "None active"
                }
            else:
                profile = {
                    "level": "Low Risk",
                    "level_color": "var(--green)",
                    "vulnerability": "WPA2 Pre-Shared Key",
                    "threats": "Password cracking susceptibility"
                }
                
        details["security"] = profile
        return jsonify(details)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/select-network', methods=['POST'])
def select_network():
    try:
        data = request.get_json() or {}
        ssid = data.get('ssid', '')
        auth = data.get('auth', '')
        enc = data.get('enc', '')
        
        if auth == 'Open' or enc == 'None':
            simulator.anomaly_threshold = 0.65
        else:
            simulator.anomaly_threshold = 0.85
            
        return jsonify({"status": "success", "monitoring": ssid, "anomaly_threshold": simulator.anomaly_threshold})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def hash_password(password, salt):
    combined = password + salt
    return hashlib.sha256(combined.encode('utf-8')).hexdigest()

@app.route('/api/backend', methods=['POST'])
def local_backend():
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify({"success": False, "error": "Invalid request payload format."})

    action = payload.get("action")
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if action == "loginUser":
            password = payload.get("password", "")
            user_code = payload.get("userCode", "").strip()
            
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({"success": False, "error": "Invalid credentials or User Code."})
                
            hashed = hash_password(password, user_code)
            if user["password_hash"] != hashed:
                return jsonify({"success": False, "error": "Invalid credentials or User Code."})
                
            if user["status"] != "ACTIVE":
                return jsonify({"success": False, "error": "Verification incomplete. Status: " + user["status"]})
                
            time_now = dt.now().strftime("%I:%M %p")
            cursor.execute('''
                INSERT INTO activities (time, user, action)
                VALUES (?, ?, ?)
            ''', (time_now, "Operator", f"User login established: {user['name']}"))
            conn.commit()
            
            return jsonify({
                "success": True,
                "name": user["name"],
                "email": user["email"],
                "userCode": user["user_code"]
            })
            
        elif action == "registerInit":
            name = payload.get("name", "").strip()
            email = payload.get("email", "").strip()
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
            if cursor.fetchone()[0] > 0:
                return jsonify({"success": False, "error": "Email address already registered."})
                
            # Generate unique code
            user_code = "".join(random.choices(string.digits, k=6))
            cursor.execute("SELECT COUNT(*) FROM users WHERE user_code = ?", (user_code,))
            while cursor.fetchone()[0] > 0:
                user_code = "".join(random.choices(string.digits, k=6))
                cursor.execute("SELECT COUNT(*) FROM users WHERE user_code = ?", (user_code,))
                
            cursor.execute('''
                INSERT INTO users (user_code, name, email, password_hash, otp, otp_expiry, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_code, name, email, "", "", "", "PENDING_PASSWORD", dt.utcnow().isoformat() + "Z"))
            conn.commit()
            return jsonify({"success": True, "userCode": user_code})
            
        elif action == "registerComplete":
            user_code = payload.get("userCode", "").strip()
            password = payload.get("password", "")
            
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User profile not found."})
                
            hashed = hash_password(password, user_code)
            otp = "".join(random.choices(string.digits, k=6))
            otp_expiry = (dt.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
            
            cursor.execute('''
                UPDATE users
                SET password_hash = ?, otp = ?, otp_expiry = ?, status = 'PENDING_OTP'
                WHERE user_code = ?
            ''', (hashed, otp, otp_expiry, user_code))
            
            time_now = dt.now().strftime("%I:%M %p")
            cursor.execute('''
                INSERT INTO activities (time, user, action)
                VALUES (?, ?, ?)
            ''', (time_now, "Operator", f"OTP verification code sent for {user['name']}"))
            conn.commit()
            
            print(f"\n==========================================")
            print(f" OTP CODE FOR {user['name']} ({user_code}): {otp} ")
            print(f"==========================================\n")
            
            return jsonify({"success": True, "otp": otp})
            
        elif action == "verifyOTP":
            user_code = payload.get("userCode", "").strip()
            otp = payload.get("otp", "").strip()
            
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User profile not found."})
                
            if user["otp"] != otp:
                return jsonify({"success": False, "error": "Incorrect verification code."})
                
            cursor.execute('''
                UPDATE users
                SET status = 'ACTIVE', otp = '', otp_expiry = ''
                WHERE user_code = ?
            ''', (user_code,))
            
            time_now = dt.now().strftime("%I:%M %p")
            cursor.execute('''
                INSERT INTO activities (time, user, action)
                VALUES (?, ?, ?)
            ''', (time_now, "Operator", f"Account verification completed for {user['name']}"))
            conn.commit()
            return jsonify({"success": True})
            
        elif action == "resendOTP":
            user_code = payload.get("userCode", "").strip()
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User profile not found."})
                
            otp = "".join(random.choices(string.digits, k=6))
            otp_expiry = (dt.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
            
            cursor.execute('''
                UPDATE users
                SET otp = ?, otp_expiry = ?
                WHERE user_code = ?
            ''', (otp, otp_expiry, user_code))
            conn.commit()
            
            print(f"\n==========================================")
            print(f" RESENT OTP CODE FOR {user['name']} ({user_code}): {otp} ")
            print(f"==========================================\n")
            return jsonify({"success": True, "otp": otp})
            
        elif action == "forgotInit":
            email = payload.get("email", "").strip()
            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "Email address not registered."})
                
            otp = "".join(random.choices(string.digits, k=6))
            otp_expiry = (dt.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
            
            cursor.execute('''
                UPDATE users
                SET otp = ?, otp_expiry = ?
                WHERE email = ?
            ''', (otp, otp_expiry, email))
            conn.commit()
            
            print(f"\n==========================================")
            print(f" RECOVERY OTP CODE FOR {user['name']}: {otp} ")
            print(f"==========================================\n")
            return jsonify({"success": True, "userCode": user["user_code"]})
            
        elif action == "resendRecoveryOTP":
            user_code = payload.get("userCode", "").strip()
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User profile not found."})
                
            otp = "".join(random.choices(string.digits, k=6))
            otp_expiry = (dt.utcnow() + timedelta(minutes=10)).isoformat() + "Z"
            
            cursor.execute('''
                UPDATE users
                SET otp = ?, otp_expiry = ?
                WHERE user_code = ?
            ''', (otp, otp_expiry, user_code))
            conn.commit()
            
            print(f"\n==========================================")
            print(f" RESENT RECOVERY OTP CODE: {otp} ")
            print(f"==========================================\n")
            return jsonify({"success": True})
            
        elif action == "forgotVerifyOTP":
            user_code = payload.get("userCode", "").strip()
            otp = payload.get("otp", "").strip()
            
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User profile not found."})
                
            if user["otp"] != otp:
                return jsonify({"success": False, "error": "Incorrect verification code."})
                
            return jsonify({"success": True})
            
        elif action == "forgotResetPassword":
            user_code = payload.get("userCode", "").strip()
            password = payload.get("password", "")
            
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User profile not found."})
                
            hashed = hash_password(password, user_code)
            cursor.execute('''
                UPDATE users
                SET password_hash = ?, otp = '', otp_expiry = '', status = 'ACTIVE'
                WHERE user_code = ?
            ''', (hashed, user_code))
            
            time_now = dt.now().strftime("%I:%M %p")
            cursor.execute('''
                INSERT INTO activities (time, user, action)
                VALUES (?, ?, ?)
            ''', (time_now, "System", f"Password reset recovery successful for {user['name']}"))
            conn.commit()
            return jsonify({"success": True})
            
        elif action == "adminLogin":
            username = payload.get("username", "").strip()
            password = payload.get("password", "")
            if username == "admin" and password == "admin123":
                return jsonify({"success": True, "token": "ADMIN_SECURE_TOKEN_2845"})
            return jsonify({"success": False, "error": "Invalid admin keys."})
            
        elif action == "adminGetUsers":
            token = payload.get("token")
            if token != "ADMIN_SECURE_TOKEN_2845":
                return jsonify({"success": False, "error": "Unauthorized session."})
                
            cursor.execute("SELECT * FROM users")
            db_users = cursor.fetchall()
            
            res_users = []
            for u in db_users:
                res_users.append({
                    "userCode": u["user_code"],
                    "name": u["name"],
                    "email": u["email"],
                    "passwordHash": u["password_hash"] or "No Hash Set",
                    "status": u["status"],
                    "createdAt": u["created_at"]
                })
            return jsonify({"success": True, "users": res_users})
            
        elif action == "adminAddUser":
            token = payload.get("token")
            if token != "ADMIN_SECURE_TOKEN_2845":
                return jsonify({"success": False, "error": "Unauthorized session."})
                
            name = payload.get("name", "").strip()
            email = payload.get("email", "").strip()
            password = payload.get("password", "")
            status = payload.get("status", "ACTIVE")
            
            cursor.execute("SELECT COUNT(*) FROM users WHERE email = ?", (email,))
            if cursor.fetchone()[0] > 0:
                return jsonify({"success": False, "error": "Email address already registered."})
                
            user_code = "".join(random.choices(string.digits, k=6))
            cursor.execute("SELECT COUNT(*) FROM users WHERE user_code = ?", (user_code,))
            while cursor.fetchone()[0] > 0:
                user_code = "".join(random.choices(string.digits, k=6))
                cursor.execute("SELECT COUNT(*) FROM users WHERE user_code = ?", (user_code,))
                
            hashed = hash_password(password, user_code)
            
            cursor.execute('''
                INSERT INTO users (user_code, name, email, password_hash, otp, otp_expiry, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_code, name, email, hashed, "", "", status, dt.utcnow().isoformat() + "Z"))
            
            time_now = dt.now().strftime("%I:%M %p")
            cursor.execute('''
                INSERT INTO activities (time, user, action)
                VALUES (?, ?, ?)
            ''', (time_now, "Admin", f"Created user profile row: {name}"))
            conn.commit()
            return jsonify({"success": True})
            
        elif action == "adminEditUser":
            token = payload.get("token")
            if token != "ADMIN_SECURE_TOKEN_2845":
                return jsonify({"success": False, "error": "Unauthorized session."})
                
            user_code = payload.get("userCode")
            name = payload.get("name", "").strip()
            email = payload.get("email", "").strip()
            password = payload.get("password", "")
            status = payload.get("status")
            
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User profile row not found."})
                
            if password:
                hashed = hash_password(password, user_code)
                cursor.execute('''
                    UPDATE users
                    SET name = ?, email = ?, password_hash = ?, status = ?
                    WHERE user_code = ?
                ''', (name, email, hashed, status, user_code))
            else:
                cursor.execute('''
                    UPDATE users
                    SET name = ?, email = ?, status = ?
                    WHERE user_code = ?
                ''', (name, email, status, user_code))
                
            time_now = dt.now().strftime("%I:%M %p")
            cursor.execute('''
                INSERT INTO activities (time, user, action)
                VALUES (?, ?, ?)
            ''', (time_now, "Admin", f"Edited user details: {name}"))
            conn.commit()
            return jsonify({"success": True})
            
        elif action == "adminDeleteUser":
            token = payload.get("token")
            if token != "ADMIN_SECURE_TOKEN_2845":
                return jsonify({"success": False, "error": "Unauthorized session."})
                
            user_code = payload.get("userCode")
            cursor.execute("SELECT * FROM users WHERE user_code = ?", (user_code,))
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User profile row not found."})
                
            cursor.execute("DELETE FROM users WHERE user_code = ?", (user_code,))
            
            time_now = dt.now().strftime("%I:%M %p")
            cursor.execute('''
                INSERT INTO activities (time, user, action)
                VALUES (?, ?, ?)
            ''', (time_now, "Admin", f"Deleted user row: {user['name']}"))
            conn.commit()
            return jsonify({"success": True})
            
        elif action == "adminGetStats":
            token = payload.get("token")
            if token != "ADMIN_SECURE_TOKEN_2845":
                return jsonify({"success": False, "error": "Unauthorized session."})
                
            cursor.execute("SELECT value FROM system_stats WHERE key = 'visitor_stats'")
            stats_row = cursor.fetchone()
            import json
            visitor_stats = json.loads(stats_row["value"]) if stats_row else [120, 180, 140, 290, 310, 480, 390, 520, 580, 510, 720, 891]
            
            cursor.execute("SELECT time, user, action FROM activities ORDER BY id DESC LIMIT 50")
            db_activities = cursor.fetchall()
            
            activities = []
            for act in db_activities:
                activities.append({
                    "time": act["time"],
                    "user": act["user"],
                    "action": act["action"]
                })
                
            return jsonify({
                "success": True,
                "visitorStats": visitor_stats,
                "activities": activities
            })
            
    except Exception as exc:
        conn.rollback()
        return jsonify({"success": False, "error": f"Database transactional error: {str(exc)}"})
    finally:
        conn.close()
        
    return jsonify({"success": False, "error": "Invalid backend action."})

if __name__ == '__main__':
    print("AI-NIDS Server running on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
