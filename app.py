import streamlit as st
import pandas as pd
import sqlite3
import os
import hashlib
from threat_utils import (
    init_db, 
    DB_FILE, 
    fetch_feeds, 
    get_existing_ips, 
    enrich_ip, 
    update_ip_sources, 
    insert_new_ip, 
    process_in_batches
)

# --- Page Configuration ---
st.set_page_config(
    page_title="Threat Intel DB", 
    page_icon="🛡️", 
    layout="wide"
)

# Ensure DB exists and is secured on load
init_db()

st.title("🛡️ Threat Intel Database & Analyzer")

# --- Stats Section ---
conn = sqlite3.connect(DB_FILE)
try:
    # Basic Counts
    total_ips = pd.read_sql_query("SELECT COUNT(*) FROM ips", conn).iloc[0, 0]
    
    # Recent Activity (Last 24h)
    recent_ips = pd.read_sql_query(
        "SELECT COUNT(*) FROM ips WHERE last_seen > date('now', '-1 day')", 
        conn
    ).iloc[0, 0]
    
    # High Risk Count
    high_risk = pd.read_sql_query(
        "SELECT COUNT(*) FROM ips WHERE risk_level LIKE '%High%' OR risk_level LIKE '%Critical%'", 
        conn
    ).iloc[0, 0]
except Exception as e:
    st.error(f"Database Error: {e}")
    total_ips = 0
    recent_ips = 0
    high_risk = 0
conn.close()

col1, col2, col3 = st.columns(3)
col1.metric("Total Unique IPs", total_ips)
col2.metric("Updated Last 24h", recent_ips)
col3.metric("High/Critical Risk", high_risk)

# --- Sidebar Configuration ---
with st.sidebar:
    st.header("Configuration")
    
    with st.expander("⚙️ Settings"):
        # Removed max_ips slider to allow unlimited scanning
        worker_threads = st.slider("Worker Threads", 1, 50, 10) # Default set to 10

    st.divider()
    st.subheader("⚠️ Danger Zone")
    
    # Secure Wipe Functionality
    with st.expander("Reset Database"):
        st.warning("This will permanently delete all threat intelligence data.")
        admin_pass = st.text_input("Enter Admin Password", type="password")
        
        if st.button("🗑️ Wipe Data", type="secondary"):
            # Hardcoded SHA256 hash for "admin123"
            # To change password: hashlib.sha256("your_password".encode()).hexdigest()
            SECURE_HASH = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
            
            input_hash = hashlib.sha256(admin_pass.encode()).hexdigest()
            
            if input_hash == SECURE_HASH:
                try:
                    if os.path.exists(DB_FILE):
                        os.remove(DB_FILE)
                        init_db() # Re-initialize immediately to set permissions
                        st.success("Database wiped and re-initialized securely.")
                        st.rerun()
                    else:
                        st.warning("Database file not found.")
                except Exception as e:
                    st.error(f"Error deleting DB: {e}")
            else:
                st.error("Incorrect Password.")

# --- Manual Run Control ---
with st.expander("⚙️ Manual Scan Control"):
    st.write("Run the scan logic manually. (This is usually done automatically by the 5 AM script)")
    
    if st.button("Run Full Scan Now", type="primary"):
        status = st.status("Fetching Feeds...", expanded=True)
        
        # 1. Fetch
        aggregated_data = fetch_feeds()
        status.write(f"Found {len(aggregated_data)} unique IPs across all feeds.")
        
        # 2. Identify New vs Old
        existing_ips = get_existing_ips()
        new_ips = [ip for ip in aggregated_data if ip not in existing_ips]
        old_ips = [ip for ip in aggregated_data if ip in existing_ips]
        
        status.write(f"New IPs to Analyze: {len(new_ips)}")
        status.write(f"Existing IPs to Update: {len(old_ips)}")
        
        # 3. Update Old (Fast)
        if old_ips:
            status.write("Updating sources for existing records...")
            progress_bar_old = st.progress(0)
            for i, ip in enumerate(old_ips):
                update_ip_sources(ip, aggregated_data[ip])
                if i % 100 == 0: 
                    progress_bar_old.progress(min((i + 1) / len(old_ips), 1.0))
            progress_bar_old.empty()
            
        # 4. Analyze New (Slow - Batched)
        if new_ips:
            status.write("Analyzing new IPs (Forensic Enrichment)...")
            progress_bar_new = st.progress(0)
            processed_count = 0
            
            # Using the batch processor from utils to respect rate limits
            # Processing all new IPs without limit
            for batch in process_in_batches(new_ips, batch_size=10, sleep_time=1):
                for ip in batch:
                    try:
                        enriched_data = enrich_ip(ip)
                        insert_new_ip(enriched_data, aggregated_data[ip])
                    except Exception as e:
                        print(f"Error processing {ip}: {e}")
                
                processed_count += len(batch)
                progress_bar_new.progress(min(processed_count / len(new_ips), 1.0))
                
            progress_bar_new.empty()
            
        status.update(label="Scan Complete", state="complete", expanded=False)
        st.rerun()

# --- Data Viewer ---
st.divider()
st.subheader("🔍 Forensic Data Explorer")

col_search, col_filter = st.columns([3, 1])
with col_search:
    search_term = st.text_input("Search IP, ASN, Hostname, or Country")
with col_filter:
    risk_filter = st.selectbox("Filter by Risk", ["All", "High (Cloud)", "Moderate (Res)"])

# Build Query
query = "SELECT * FROM ips WHERE 1=1"
params = []

if risk_filter != "All":
    query += " AND risk_level = ?"
    params.append(risk_filter)

if search_term:
    query += """ AND (
        ip_address LIKE ? OR 
        asn LIKE ? OR 
        country LIKE ? OR 
        hostname LIKE ? OR
        isp_name LIKE ?
    )"""
    search_wildcard = f"%{search_term}%"
    params.extend([search_wildcard] * 5)

query += " ORDER BY last_seen DESC LIMIT 1000"

# Execute Query
conn = sqlite3.connect(DB_FILE)
df = pd.read_sql_query(query, conn, params=params)

if not df.empty:
    # --- Fetch Detailed Sightings for Pivot ---
    ip_list = df['ip_address'].tolist()
    
    if ip_list:
        try:
            # Create parameters string for IN clause
            placeholders = ','.join(['?'] * len(ip_list))
            
            # Pivot Query: Get max sighted_at for each source/ip pair
            sighting_query = f"""
                SELECT ip_address, source_feed, MAX(sighted_at) as last_seen_source
                FROM sightings
                WHERE ip_address IN ({placeholders})
                GROUP BY ip_address, source_feed
            """
            
            sightings_df = pd.read_sql_query(sighting_query, conn, params=ip_list)
            
            if not sightings_df.empty:
                # Pivot: IP (rows) x Source (cols) = Last Seen Time
                pivot_df = sightings_df.pivot(index='ip_address', columns='source_feed', values='last_seen_source')
                
                # Calculate Source Count (Number of feeds containing this IP)
                pivot_df['Source_Count'] = pivot_df.notna().sum(axis=1)
                
                # Merge Pivot data back into main DF
                df = pd.merge(df, pivot_df, on='ip_address', how='left')
                
                # Fill NaN in Source_Count with 0 (for consistency)
                df['Source_Count'] = df['Source_Count'].fillna(0).astype(int)
                
        except Exception as e:
            st.error(f"Error generating source breakdown: {e}")

conn.close()

if not df.empty:
    # Reorder Columns for readability
    # Prioritize: IP, Source Count, Risk, Country... then dynamic Source columns
    core_cols = ['ip_address', 'Source_Count', 'risk_level', 'country', 'isp_name', 'host_type', 'last_seen']
    
    # Find which columns from core_cols actually exist in df
    available_core = [c for c in core_cols if c in df.columns]
    
    # Get all other columns (including the dynamic feed names)
    # Removed exclusion for 'sources' so it appears in the table
    other_cols = [c for c in df.columns if c not in available_core] 
    
    # Combine
    final_cols = available_core + other_cols
    df = df[final_cols]

    # Formatting for display
    st.dataframe(
        df.style.applymap(
            lambda x: 'background-color: #ffcdd2' if 'High' in str(x) else '',
            subset=['risk_level']
        ),
        use_container_width=True
    )
    
    # Download Button
    st.download_button(
        label="📥 Download Current View (CSV)",
        data=df.to_csv(index=False).encode('utf-8'),
        file_name="threat_intel_export.csv",
        mime="text/csv"
    )
else:
    st.info("No data found matching your criteria.")
