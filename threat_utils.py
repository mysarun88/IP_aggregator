import sqlite3
import requests
import re
import socket
import time
import pandas as pd
import os
import csv
import sys
import stat  # Added for file permission security
from datetime import datetime
from collections import defaultdict
from ipwhois import IPWhois
from git import Repo, GitCommandError

# --- Configuration ---
DB_FILE = "threat_intel.db"
DATA_DIR = "data_exports" # Folder for CSV exports

# Expanded Feed List
FEEDS = [
    {"name": "Blocklist.de (RDP)", "url": "https://lists.blocklist.de/lists/rdp.txt"},
    {"name": "GreenSnow", "url": "http://blocklist.greensnow.co/greensnow.txt"},
    {"name": "CINS Army", "url": "http://cinsscore.com/list/ci-badguys.txt"},
    {"name": "IPSum Level 3", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"},
    {"name": "DigitalSide MISP", "url": "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt"},
    {"name": "Feodo Tracker", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"},
    {"name": "ThreatFox", "url": "https://threatfox.abuse.ch/export/csv/ip-port/recent/"},
    {"name": "URLHaus", "url": "https://urlhaus.abuse.ch/downloads/hostfile/"},
    {"name": "Emerging Threats", "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"},
    {"name": "FireHOL Level 1", "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"}
]

HOSTING_KEYWORDS = [
    'CLOUD', 'VPS', 'HOSTING', 'DATACENTER', 'DIGITALOCEAN', 'AMAZON', 'AWS', 
    'GOOGLE', 'MICROSOFT', 'AZURE', 'OVH', 'HETZNER', 'ALIBABA', 'TENCENT', 
    'ORACLE', 'LINODE', 'VULTR', 'LEASEWEB', 'RACKSPACE', 'AKAMAI'
]

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# --- Database Management ---

def init_db():
    """Initializes DB, handles schema migrations, and secures the file."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # 1. Create Tables (if they don't exist)
    c.execute('''
        CREATE TABLE IF NOT EXISTS ips (
            ip_address TEXT PRIMARY KEY,
            first_seen DATETIME,
            last_seen DATETIME,
            sources TEXT,
            asn TEXT,
            isp_name TEXT,
            country TEXT,
            city TEXT,
            hostname TEXT,
            host_type TEXT,
            risk_level TEXT,
            abuse_contact TEXT,
            cidr TEXT,
            asn_registry TEXT,
            updated_date TEXT
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            source_feed TEXT,
            sighted_at DATETIME,
            FOREIGN KEY(ip_address) REFERENCES ips(ip_address)
        )
    ''')
    
    # 2. Schema Migration: Check for 'sources' column
    try:
        c.execute("SELECT sources FROM ips LIMIT 1")
    except sqlite3.OperationalError:
        print("[-] Performing Schema Migration: Adding 'sources' column...")
        c.execute("ALTER TABLE ips ADD COLUMN sources TEXT")
        
    conn.commit()
    conn.close()

    # 3. Security: Restrict file permissions to owner only (chmod 600)
    try:
        if os.path.exists(DB_FILE):
            os.chmod(DB_FILE, stat.S_IRUSR | stat.S_IWUSR)
            print(f"[*] Secured database file permissions for {DB_FILE}")
    except Exception as e:
        print(f"[!] Warning: Could not set secure permissions on DB: {e}")

def get_existing_ips():
    """Returns a set of all IPs currently in the DB."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute("SELECT ip_address FROM ips")
        ips = {row[0] for row in c.fetchall()}
    except sqlite3.OperationalError:
        ips = set()
    conn.close()
    return ips

def update_ip_sources(ip, new_sources):
    """Updates the 'sources' column merging old and new sources."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT sources FROM ips WHERE ip_address = ?", (ip,))
    row = c.fetchone()
    
    current_sources = set()
    if row and row[0]:
        # Handle potential empty or malformed source strings
        current_sources = set(s.strip() for s in row[0].split(",") if s.strip())
    
    # Add new sources
    current_sources.update(new_sources)
    
    updated_str = ", ".join(sorted(current_sources))
    c.execute("UPDATE ips SET sources = ?, last_seen = ? WHERE ip_address = ?", 
              (updated_str, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip))
    
    conn.commit()
    conn.close()

def insert_new_ip(data, sources):
    """Inserts a completely new IP record and commits immediately."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_str = ", ".join(sorted(sources))
    
    try:
        c.execute('''
            INSERT INTO ips (
                ip_address, first_seen, last_seen, sources,
                asn, isp_name, country, city, hostname, host_type, 
                risk_level, abuse_contact, cidr, asn_registry, updated_date
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['IP'], now, now, source_str,
            data.get('ASN'), data.get('ISP_Name'), data.get('Country'), data.get('City'),
            data.get('Hostname'), data.get('Host_Type'), data.get('Risk_Level'),
            data.get('Abuse_Contact'), data.get('CIDR'), data.get('ASN_Registry'), data.get('Updated_Date')
        ))
        conn.commit() # <--- Data is saved here, per IP
    except sqlite3.IntegrityError:
        # If IP was added by another process in the milliseconds between check and insert
        update_ip_sources(data['IP'], sources)
    finally:
        conn.close()

# --- Parsing & Enrichment ---

def fetch_feeds():
    """Downloads all feeds and returns a dict: {ip: [source1, source2]}"""
    print("[-] Fetching feeds...")
    aggregated = defaultdict(set)
    
    for feed in FEEDS:
        try:
            r = requests.get(feed['url'], timeout=10)
            if r.status_code == 200:
                ips = set(IP_PATTERN.findall(r.text))
                for ip in ips:
                    if not ip.startswith(('127.', '10.', '192.168.')): 
                        aggregated[ip].add(feed['name'])
        except Exception as e:
            print(f"    [!] Failed to fetch {feed['name']}: {e}")
            
    return aggregated

def enrich_ip(ip):
    """Deep Forensic Analysis (Whois + RDAP + Reverse DNS)."""
    data = {
        'IP': ip, 
        'ASN': 'Unknown', 'ISP_Name': 'Unknown', 'Country': 'XX',
        'City': 'Unknown', 'Hostname': 'Unknown', 'Abuse_Contact': 'Unknown', 
        'Host_Type': 'Unknown', 'CIDR': 'Unknown', 'ASN_Registry': 'Unknown',
        'Updated_Date': 'Unknown', 'Risk_Level': 'Unknown'
    }
    
    # 1. Reverse DNS
    try:
        socket.setdefaulttimeout(2)
        data['Hostname'] = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    # 2. RDAP/Whois
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1, retry_count=1)
        
        data['ASN'] = res.get('asn', 'Unknown')
        data['ISP_Name'] = res.get('asn_description', 'Unknown')
        data['Country'] = res.get('asn_country_code', 'XX')
        data['ASN_Registry'] = res.get('asn_registry', 'Unknown')
        
        network = res.get('network', {})
        data['CIDR'] = network.get('cidr', 'Unknown')
        data['Updated_Date'] = network.get('updated', 'Unknown')
        data['City'] = network.get('city', 'Unknown')

        # Extract Abuse Contact
        objects = res.get('objects', {})
        for _, val in objects.items():
            contact = val.get('contact', {})
            if 'abuse' in val.get('roles', []) or 'abuse' in str(contact).lower():
                emails = contact.get('email')
                if emails:
                    data['Abuse_Contact'] = emails[0].get('value')
                    break
                    
    except Exception:
        pass

    # 3. Heuristics
    isp_upper = str(data['ISP_Name']).upper()
    host_upper = str(data['Hostname']).upper()
    
    if any(k in isp_upper or k in host_upper for k in HOSTING_KEYWORDS):
        data['Host_Type'] = 'Cloud/Hosting'
        data['Risk_Level'] = 'High (Cloud)'
    else:
        data['Host_Type'] = 'Residential/ISP'
        data['Risk_Level'] = 'Moderate (Res)'
        
    return data

def process_in_batches(ip_list, batch_size=10, sleep_time=2):
    """Generator that yields batches and sleeps to respect rate limits."""
    total = len(ip_list)
    for i in range(0, total, batch_size):
        batch = ip_list[i:i + batch_size]
        yield batch
        if i + batch_size < total:
            time.sleep(sleep_time)

def run_forensic_analysis(new_ips, aggregated_data, batch_size=10, sleep_time=2):
    """
    Runs the enrichment process with live status updates (Current IP, Progress, ETA).
    """
    total_ips = len(new_ips)
    if total_ips == 0:
        print("[-] No new IPs to analyze.")
        return

    print(f"[*] Starting forensic analysis for {total_ips} IPs...")
    start_time = time.time()
    processed_count = 0

    # Using the batch processor to handle rate limiting sleeps
    for batch in process_in_batches(new_ips, batch_size, sleep_time):
        for ip in batch:
            # Calculate ETA
            elapsed_time = time.time() - start_time
            if processed_count > 0:
                avg_time = elapsed_time / processed_count
                remaining = total_ips - processed_count
                eta_seconds = int(avg_time * remaining)
                eta_str = str(datetime.utcfromtimestamp(eta_seconds).strftime('%H:%M:%S'))
            else:
                eta_str = "Calculating..."

            # Live Status Line (Overwrites previous line)
            status_msg = (
                f"    -> Analyzing: {ip:<15} | "
                f"Left: {total_ips - processed_count:<5} | "
                f"ETA: {eta_str}   "
            )
            sys.stdout.write("\r" + status_msg)
            sys.stdout.flush()

            try:
                enriched = enrich_ip(ip)
                # This inserts and commits immediately.
                insert_new_ip(enriched, aggregated_data[ip])
            except Exception as e:
                sys.stdout.write(f"\n[!] Error processing {ip}: {e}\n")

            processed_count += 1
    
    total_time = time.time() - start_time
    print(f"\n[+] Analysis complete. Total run time: {str(datetime.utcfromtimestamp(total_time).strftime('%H:%M:%S'))}")

def export_to_github_repo():
    """Exports DB to CSV and commits to Git."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        
    today = datetime.now().strftime('%Y-%m-%d')
    filename = os.path.join(DATA_DIR, f"threat_intel_{today}.csv")
    
    conn = sqlite3.connect(DB_FILE)
    try:
        df = pd.read_sql_query("SELECT * FROM ips", conn)
    except Exception:
        return "Error reading DB."
    finally:
        conn.close()
    
    if df.empty:
        return "No data to export."
        
    df.to_csv(filename, index=False)
    
    try:
        repo = Repo('.') 
        repo.index.add([filename])
        repo.index.commit(f"Daily Threat Intel Update: {today}")
        # repo.remotes.origin.push() # Uncomment if keys are configured
        return f"Exported {filename}."
    except Exception as e:
        return f"Exported CSV but Git failed: {e}"
