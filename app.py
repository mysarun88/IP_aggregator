import streamlit as st
import pandas as pd
import os
import hashlib
from threat_utils import (
    init_storage, 
    STORAGE_FILE, 
    fetch_feeds, 
    get_existing_ips, 
    enrich_ip, 
    update_ip_sources, 
    insert_new_ip, 
    process_in_batches
)

# --- Page Configuration ---
st.set_page_config(
    page_title="Threat Intel DB (CSV)", 
    page_icon="🛡️", 
    layout="wide"
)

# Ensure CSV exists
init_storage()

st.title("🛡️ Threat Intel Database & Analyzer")

# --- Stats Section ---
total_ips = 0
recent_ips = 0
high_risk = 0

if os.path.exists(STORAGE_FILE) and os.path.getsize(STORAGE_FILE) > 0:
    try:
        # Read strictly what we need to avoid massive memory usage on load
        df_stats = pd.read_csv(STORAGE_FILE, usecols=['ip_address', 'last_seen', 'risk_level'])
        
        total_ips = len(df_stats)
        
        # Convert last_seen to datetime for filtering
        df_stats['last_seen'] = pd.to_datetime(df_stats['last_seen'], errors='coerce')
        recent_ips = len(df_stats[df_stats['last_seen'] > (pd.Timestamp.now() - pd.Timedelta(days=1))])
        
        high_risk = len(df_stats[
            df_stats['risk_level'].astype(str).str.contains('High', case=False) | 
            df_stats['risk_level'].astype(str).str.contains('Critical', case=False)
        ])
    except Exception as e:
        st.error(f"Error reading CSV for stats: {e}")

col1, col2, col3 = st.columns(3)
col1.metric("Total Unique IPs", total_ips)
col2.metric("Updated Last 24h", recent_ips)
col3.metric("High/Critical Risk", high_risk)

# --- Sidebar Configuration ---
with st.sidebar:
    st.header("Configuration")
    
    with st.expander("⚙️ Settings"):
        worker_threads = st.slider("Worker Threads", 1, 50, 10)

    st.divider()
    st.subheader("⚠️ Danger Zone")
    
    with st.expander("Reset Database"):
        st.warning("This will delete threat_intel.csv.")
        admin_pass = st.text_input("Enter Admin Password", type="password")
        
        if st.button("🗑️ Wipe Data", type="secondary"):
            SECURE_HASH = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
            input_hash = hashlib.sha256(admin_pass.encode()).hexdigest()
            
            if input_hash == SECURE_HASH:
                try:
                    if os.path.exists(STORAGE_FILE):
                        os.remove(STORAGE_FILE)
                        init_storage()
                        st.success("Storage wiped.")
                        st.rerun()
                    else:
                        st.warning("File not found.")
                except Exception as e:
                    st.error(f"Error: {e}")
            else:
                st.error("Incorrect Password.")

# --- Manual Run Control ---
with st.expander("⚙️ Manual Scan Control"):
    st.write("Run the scan logic manually.")
    
    if st.button("Run Full Scan Now", type="primary"):
        status = st.status("Fetching Feeds...", expanded=True)
        
        # 1. Fetch
        aggregated_data = fetch_feeds()
        status.write(f"Found {len(aggregated_data)} unique IPs.")
        
        # 2. Identify New vs Old
        existing_ips = get_existing_ips()
        new_ips = [ip for ip in aggregated_data if ip not in existing_ips]
        old_ips = [ip for ip in aggregated_data if ip in existing_ips]
        
        status.write(f"New IPs: {len(new_ips)} | Existing IPs: {len(old_ips)}")
        
        # 3. Update Old
        if old_ips:
            status.write("Updating existing records (CSV rewrite)...")
            progress_bar_old = st.progress(0)
            # Note: Bulk updating CSV row-by-row is slow. 
            # For 1000+ IPs, this might lag.
            for i, ip in enumerate(old_ips):
                update_ip_sources(ip, aggregated_data[ip])
                if i % 50 == 0: 
                    progress_bar_old.progress(min((i + 1) / len(old_ips), 1.0))
            progress_bar_old.empty()
            
        # 4. Analyze New
        if new_ips:
            status.write("Analyzing new IPs...")
            progress_bar_new = st.progress(0)
            processed_count = 0
            
            for batch in process_in_batches(new_ips, batch_size=10, sleep_time=1):
                for ip in batch:
                    try:
                        enriched_data = enrich_ip(ip)
                        insert_new_ip(enriched_data, aggregated_data[ip])
                    except Exception as e:
                        print(f"Error: {e}")
                
                processed_count += len(batch)
                progress_bar_new.progress(min(processed_count / len(new_ips), 1.0))
                
            progress_bar_new.empty()
            
        status.update(label="Scan Complete", state="complete", expanded=False)
        st.rerun()

# --- Data Viewer ---
st.divider()
st.subheader("🔍 Forensic Data Explorer")

if os.path.exists(STORAGE_FILE) and os.path.getsize(STORAGE_FILE) > 0:
    # Load Data
    df = pd.read_csv(STORAGE_FILE)
    
    # Filters
    col_search, col_filter = st.columns([3, 1])
    with col_search:
        search_term = st.text_input("Search")
    with col_filter:
        risk_filter = st.selectbox("Filter by Risk", ["All", "High", "Moderate", "Low"])

    # Apply Search
    if search_term:
        df = df[
            df.astype(str).apply(lambda x: x.str.contains(search_term, case=False)).any(axis=1)
        ]
    
    if risk_filter != "All":
        df = df[df['risk_level'].astype(str).str.contains(risk_filter, case=False)]

    # Dynamic Source Counts (calculated on fly from sources string)
    df['Source_Count'] = df['sources'].astype(str).apply(lambda x: len(x.split(',')) if x != 'nan' else 0)
    
    # Display
    st.dataframe(
        df.style.applymap(
            lambda x: 'background-color: #ffcdd2' if 'High' in str(x) else '',
            subset=['risk_level']
        ),
        use_container_width=True
    )
    
    st.download_button(
        label="📥 Download CSV",
        data=df.to_csv(index=False).encode('utf-8'),
        file_name="threat_intel_export.csv",
        mime="text/csv"
    )
else:
    st.info("Database is empty.")
