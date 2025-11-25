import streamlit as st
import requests
import re
import socket
import concurrent.futures
import pandas as pd
import sqlite3
import os
from collections import defaultdict
from datetime import datetime
from ipwhois import IPWhois

# --- Page Configuration ---
st.set_page_config(
    page_title="RDP Threat Intel Aggregator (DB)", 
    page_icon="🛡️", 
    layout="wide"
)

# --- Constants & Config ---
DB_FILE = "threat_intel.db"

FEEDS = [
    # Standard RDP/Brute Force Feeds
    {"name": "Blocklist.de (RDP)", "url": "https://lists.blocklist.de/lists/rdp.txt", "type": "simple"},
    {"name": "GreenSnow", "url": "http://blocklist.greensnow.co/greensnow.txt", "type": "simple"},
    {"name": "CINS Army", "url": "http://cinsscore.com/list/ci-badguys.txt", "type": "simple"},
    {"name": "IPSum Level 3", "url": "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt", "type": "simple"},
    
    # MISP / OSINT Feeds (New)
    # DigitalSide is a public feed often used in MISP instances
    {"name": "DigitalSide MISP Feed", "url": "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt", "type": "simple"},
    # Feodo Tracker is highly reliable for botnets (often RDP sources)
    {"name": "Feodo Tracker (Abuse.ch)", "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "type": "simple"}
]

HOSTING_KEYWORDS = [
    'CLOUD', 'VPS', 'HOSTING', 'DATACENTER', 'DIGITALOCEAN', 'AMAZON', 'AWS', 
    'GOOGLE', 'MICROSOFT', 'AZURE', 'OVH', 'HETZNER', 'ALIBABA', 'TENCENT', 
    'ORACLE', 'LINODE', 'VULTR', 'LEASEWEB'
]

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b')

# --- Database Functions ---

def init_db():
    """Initializes the SQLite database with a scalable schema."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # 1. Table: IP Entities (Stores static/slow-changing data)
    c.execute('''
        CREATE TABLE IF NOT EXISTS ips (
            ip_address TEXT PRIMARY KEY,
            first_seen DATETIME,
            last_seen DATETIME,
            asn TEXT,
            isp_name TEXT,
            country TEXT,
            city TEXT,
            hostname TEXT,
            host_type TEXT,
            risk_level TEXT,
            abuse_contact TEXT
        )
    ''')
    
    # 2. Table: Sightings (Stores every time an IP appears in a feed)
    # This is the "Scalable" part. We track events separately from entities.
    c.execute('''
        CREATE TABLE IF NOT EXISTS sightings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            source_feed TEXT,
            sighted_at DATETIME,
            FOREIGN KEY(ip_address) REFERENCES ips(ip_address)
        )
    ''')
    
    # Index for faster lookups
    c.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON sightings(ip_address)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_sighted_at ON sightings(sighted_at)')
    
    conn.commit()
    conn.close()

def db_upsert_ip(data):
    """Inserts or Updates an IP record."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Check if exists
    c.execute("SELECT first_seen FROM ips WHERE ip_address = ?", (data['IP'],))
    row = c.fetchone()
    
    if row:
        # Update Last Seen and Enrichment Data (if it changed)
        c.execute('''
            UPDATE ips SET 
                last_seen = ?, 
                asn = ?, isp_name = ?, country = ?, city = ?, hostname = ?, host_type = ?, risk_level = ?, abuse_contact = ?
            WHERE ip_address = ?
        ''', (
            now, 
            data.get('ASN'), data.get('ISP_Name'), data.get('Country'), data.get('City'), 
            data.get('Hostname'), data.get('Host_Type'), data.get('Risk_Level'), data.get('Abuse_Contact'),
            data['IP']
        ))
    else:
        # Insert New
        c.execute('''
            INSERT INTO ips (ip_address, first_seen, last_seen, asn, isp_name, country, city, hostname, host_type, risk_level, abuse_contact)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['IP'], now, now,
            data.get('ASN'), data.get('ISP_Name'), data.get('Country'), data.get('City'), 
            data.get('Hostname'), data.get('Host_Type'), data.get('Risk_Level'), data.get('Abuse_Contact')
        ))
    
    conn.commit()
    conn.close()

def db_add_sightings(ip, feeds_list):
    """Adds sighting records for an IP."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for feed in feeds_list:
        c.execute("INSERT INTO sightings (ip_address, source_feed, sighted_at) VALUES (?, ?, ?)", (ip, feed, now))
        
    conn.commit()
    conn.close()

def db_get_report(limit=1000):
    """Fetches the consolidated report from DB."""
    conn = sqlite3.connect(DB_FILE)
    
    # Complex query to join IP data with "Last Reported Malicious" stats
    query = f'''
        SELECT 
            i.ip_address, i.risk_level, i.country, i.isp_name, 
            i.host_type, i.first_seen, i.last_seen,
            (SELECT MAX(sighted_at) FROM sightings s WHERE s.ip_address = i.ip_address) as last_reported_malicious,
            (SELECT COUNT(*) FROM sightings s WHERE s.ip_address = i.ip_address) as total_sightings,
            i.hostname, i.asn, i.city
        FROM ips i
        ORDER BY last_reported_malicious DESC
        LIMIT {limit}
    '''
    df = pd.read_sql_query(query, conn)
    conn.close()
    return df

# --- Helper Functions ---

@st.cache_data(ttl=600)
def fetch_feed_data(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception:
        return None

def parse_ips(content):
    ips = set()
    if not content: return ips
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//')): continue
        match = IP_PATTERN.search(line)
        if match:
            ips.add(match.group(0).split('/')[0])
    return ips

def get_reverse_dns(ip):
    try:
        socket.setdefaulttimeout(2)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "Unknown"

def get_osint_data(ip):
    data = {
        'IP': ip, 'ASN': 'Unknown', 'ISP_Name': 'Unknown', 'Country': 'XX',
        'City': 'Unknown', 'Hostname': 'Unknown', 'Abuse_Contact': 'Unknown', 'Host_Type': 'Unknown'
    }
    data['Hostname'] = get_reverse_dns(ip)
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1, retry_count=1, rate_limit_timeout=0)
        data['ASN'] = results.get('asn', 'Unknown')
        data['ISP_Name'] = results.get('asn_description', 'Unknown')
        data['Country'] = results.get('asn_country_code', 'XX')
        data['City'] = results.get('network', {}).get('city', 'Unknown')
        
        email_found = None
        objects = results.get('objects', {})
        for _, obj_val in objects.items():
            roles = obj_val.get('roles', [])
            contact = obj_val.get('contact', {})
            if 'abuse' in roles or 'technical' in roles:
                emails = contact.get('email')
                if emails:
                    email_found = emails[0].get('value')
                    break
        if email_found: data['Abuse_Contact'] = email_found
            
    except Exception: pass

    isp_upper = str(data['ISP_Name']).upper()
    hostname_upper = str(data['Hostname']).upper()
    is_cloud = any(k in isp_upper or k in hostname_upper for k in HOSTING_KEYWORDS)
    data['Host_Type'] = 'Cloud/Hosting' if is_cloud else 'Residential/ISP'
    
    return data

def calculate_risk(count):
    if count == 1: return "Low"
    elif count < 5: return "Moderate"
    elif count < 15: return "High"
    else: return "Critical"

# --- Main App UI ---

# Initialize DB on app start
init_db()

st.title("🛡️ RDP Threat Intel Aggregator (DB Backend)")
st.markdown("""
This system aggregates threat intelligence from multiple sources (including **MISP/DigitalSide**), 
performs forensic enrichment, and stores the history in a local **SQLite Database**.
""")

with st.sidebar:
    st.header("Configuration")
    max_ips = st.slider("Limit Analysis Count", 10, 2000, 100)
    worker_threads = st.slider("Worker Threads", 1, 30, 15)
    
    st.divider()
    if st.button("🗑️ Reset Database"):
        try:
            if os.path.exists(DB_FILE):
                os.remove(DB_FILE)
                init_db()
                st.success("Database cleared and re-initialized.")
        except Exception as e:
            st.error(f"Error: {e}")

col_scan, col_refresh = st.columns([1, 5])
with col_scan:
    start_btn = st.button("🚀 Start Scan", type="primary")
with col_refresh:
    refresh_btn = st.button("🔄 Refresh Table (Read DB)")

# --- Scanning Logic ---
if start_btn:
    status_container = st.status("Starting Aggregation...", expanded=True)
    aggregated_data = defaultdict(list)
    
    # 1. Aggregate Feeds
    all_source_names = [f['name'] for f in FEEDS]
    for feed in FEEDS:
        status_container.write(f"Fetching {feed['name']}...")
        content = fetch_feed_data(feed['url'])
        if content:
            found_ips = parse_ips(content)
            for ip in found_ips:
                aggregated_data[ip].append(feed['name'])
    
    unique_ips = list(aggregated_data.keys())
    status_container.write(f"Found {len(unique_ips)} unique IPs. Prioritizing...")
    
    # Prioritize: IPs in multiple lists > New IPs
    # (In a real app, we might query the DB to skip recently updated IPs, but here we refresh them)
    sorted_ips = sorted(unique_ips, key=lambda ip: len(aggregated_data[ip]), reverse=True)
    ips_to_process = sorted_ips[:max_ips]
    
    # 2. Enrich and Store
    progress_bar = st.progress(0)
    status_container.update(label="Enriching and Storing to Database...", state="running")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=worker_threads) as executor:
        future_to_ip = {executor.submit(get_osint_data, ip): ip for ip in ips_to_process}
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            data = future.result()
            ip = data['IP']
            
            # Calculate local risk based on feed appearances (quick heuristic)
            data['Risk_Level'] = calculate_risk(len(aggregated_data[ip]))
            
            # Save to DB
            db_upsert_ip(data)
            db_add_sightings(ip, aggregated_data[ip])
            
            completed += 1
            progress_bar.progress(completed / len(ips_to_process))
            
    status_container.update(label="Scan Complete! Database Updated.", state="complete", expanded=False)
    progress_bar.empty()
    st.success("Scan finished. Data has been committed to `threat_intel.db`.")

# --- Reporting Logic (Reads from DB) ---
st.divider()
st.subheader("📊 Threat Database Report")

try:
    df = db_get_report(limit=5000)
    
    if not df.empty:
        # Metrics
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total IPs in DB", len(df))
        c2.metric("High/Crit Risk", len(df[df['risk_level'].isin(['High', 'Critical'])]))
        c3.metric("Cloud Hosts", len(df[df['host_type'] == 'Cloud/Hosting']))
        c4.metric("Top Country", df['country'].mode()[0] if not df.empty else "-")
        
        # Filters
        filter_risk = st.multiselect("Filter by Risk", df['risk_level'].unique())
        if filter_risk:
            df = df[df['risk_level'].isin(filter_risk)]
            
        # Display
        st.dataframe(
            df.style.applymap(
                lambda x: 'background-color: #ffcdd2' if x == 'Critical' else 
                          ('background-color: #fff9c4' if x == 'High' else ''),
                subset=['risk_level']
            ),
            use_container_width=True
        )
        
        # Download
        csv_data = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download Full DB Report (CSV)", csv_data, "threat_intel_db.csv", "text/csv")
    else:
        st.info("Database is empty. Run a scan to populate it.")
        
except Exception as e:
    st.error(f"Database Error: {e}")