import time
import logging
from datetime import datetime
from threat_utils import (
    init_db, fetch_feeds, get_existing_ips, 
    update_ip_sources, enrich_ip, insert_new_ip, 
    process_in_batches, export_to_github_repo
)

# Configure Logging
logging.basicConfig(
    filename='daily_scan.log', 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_daily_job():
    logging.info("--- Starting Daily Scan Job ---")
    print(f"[{datetime.now()}] Starting Daily Scan...")
    
    # Ensure DB exists
    init_db()
    
    # 1. Fetch Feeds
    aggregated_data = fetch_feeds()
    logging.info(f"Fetched {len(aggregated_data)} unique IPs from feeds.")
    
    # 2. Separate New vs Old
    existing_ips = get_existing_ips()
    new_ips = [ip for ip in aggregated_data if ip not in existing_ips]
    old_ips = [ip for ip in aggregated_data if ip in existing_ips]
    
    print(f"Existing IPs to update: {len(old_ips)}")
    print(f"New IPs to analyze: {len(new_ips)}")
    
    # 3. Update Old IPs (Fast - No external API calls needed usually)
    # We just update the 'sources' and 'last_seen'
    count = 0
    for ip in old_ips:
        update_ip_sources(ip, aggregated_data[ip])
        count += 1
        if count % 1000 == 0:
            print(f"Updated {count} existing records...")
            
    logging.info(f"Updated {len(old_ips)} existing records.")
    
    # 4. Analyze New IPs (Slow - Batched with Sleeps)
    if new_ips:
        print("Starting enrichment for new IPs...")
        count = 0
        # Batch size 10, sleep 2 seconds = ~300 IPs/minute safe rate
        for batch in process_in_batches(new_ips, batch_size=10, sleep_time=2):
            for ip in batch:
                try:
                    enriched = enrich_ip(ip)
                    insert_new_ip(enriched, aggregated_data[ip])
                except Exception as e:
                    logging.error(f"Error processing {ip}: {e}")
            
            count += len(batch)
            print(f"Enriched {count}/{len(new_ips)} IPs...", end='\r')
            
        logging.info(f"Enriched {len(new_ips)} new IPs.")
        print("\nEnrichment complete.")
    
    # 5. Export and Commit
    result = export_to_github_repo()
    logging.info(f"Git Operation: {result}")
    print(f"Git Operation: {result}")
    
    logging.info("--- Job Complete ---")

if __name__ == "__main__":
    # If running manually or via simple cron
    run_daily_job()
    
    # OPTIONAL: If you want this script to stay alive and run loop (not recommended if using cron)
    # while True:
    #     now = datetime.now()
    #     if now.hour == 5 and now.minute == 0:
    #         run_daily_job()
    #         time.sleep(61) # Prevent double run
    #     time.sleep(50)
