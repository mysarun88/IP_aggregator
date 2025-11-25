import sqlite3
import requests
import re
import socket
import time
import pandas as pd
import os
import csv
from datetime import datetime
from collections import defaultdict
from ipwhois import IPWhois
from git import Repo, GitCommandError  # Requires: pip install gitpython

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
    {"name": "Emerging Threats", "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"}
]

HOSTING_KEYWORDS = [
    'CLOUD', 'VPS', 'HOSTING', 'DATACENTER', 'DIGITALOCEAN', 'AMAZON', 'AWS', 
    'GOOGLE', 'MICROSOFT', 'AZURE', 'OVH', 'HETZNER', 'ALIBABA', 'TENCENT', 
    'ORACLE', 'LINODE', 'VULTR', 'LEASEWEB', 'RACKSPACE', 'AKAMAI'
]

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# --- Database Management ---

def init_db():
    """Initializes DB with the Source Column."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # Main Entity Table
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
    
    # Sightings Table (Event Log)
    c.execute('''
        CREATE TABLE IF NOT EXISTS sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            source_feed TEXT,
            sighted_at DATETIME,
            FOREIGN KEY(ip_address) REFERENCES ips(ip_address)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_existing_ips():
    """Returns a set of all IPs currently in the DB."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT ip_address FROM ips")
    ips = {row[0] for row in c.fetchall()}
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
        current_sources = set(row[0].split(", "))
    
    # Add new sources
    current_sources.update(new_sources)
    
    updated_str = ", ".join(sorted(current_sources))
    c.execute("UPDATE ips SET sources = ?, last_seen = ? WHERE ip_address = ?", 
              (updated_str, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip))
    
    conn.commit()
    conn.close()

def insert_new_ip(data, sources):
    """Inserts a completely new IP record."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    source_str = ", ".join(sorted(sources))
    
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
    conn.commit()
    conn.close()

# --- Parsing & Enrichment ---

def fetch_feeds():
    """Downloads all feeds and returns a dict: {ip: [source1, source2]}"""
    print("[-] Fetching feeds...")
    aggregated = defaultdict(set)
    
    for feed in FEEDS:
        try:
            # print(f"    Fetching {feed['name']}...")
            r = requests.get(feed['url'], timeout=10)
            if r.status_code == 200:
                ips = set(IP_PATTERN.findall(r.text))
                for ip in ips:
                    # Filter out local IPs or versions
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
        # depth=1 fetches specific org data. 
        # retry_count=1 to fail fast if server is blocking us.
        res = obj.lookup_rdap(depth=1, retry_count=1)
        
        data['ASN'] = res.get('asn', 'Unknown')
        data['ISP_Name'] = res.get('asn_description', 'Unknown')
        data['Country'] = res.get('asn_country_code', 'XX')
        data['ASN_Registry'] = res.get('asn_registry', 'Unknown')
        
        network = res.get('network', {})
        data['CIDR'] = network.get('cidr', 'Unknown')
        data['Updated_Date'] = network.get('updated', 'Unknown') # When was this block last changed?
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

def export_to_github_repo():
    """Exports DB to CSV and commits to Git."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)
        
    today = datetime.now().strftime('%Y-%m-%d')
    filename = os.path.join(DATA_DIR, f"threat_intel_{today}.csv")
    
    # Dump DB to CSV
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM ips", conn)
    conn.close()
    
    if df.empty:
        return "No data to export."
        
    df.to_csv(filename, index=False)
    
    # Git Operations
    try:
        repo = Repo('.')  # Initialize repo object for current dir
        repo.index.add([filename])
        repo.index.commit(f"Daily Threat Intel Update: {today}")
        # Uncomment the next line if you have a remote configured and keys set up
        # repo.remotes.origin.push() 
        return f"Exported {filename} and committed to local git."
    except Exception as e:
        return f"Exported CSV but Git failed: {e}"
