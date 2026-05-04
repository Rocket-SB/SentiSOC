import requests
import time
import random
from datetime import datetime, timezone, timedelta
from requests.exceptions import ConnectionError, ReadTimeout

AUTH_URL = "http://localhost:5001/api/auth/login"
RESERVATION_URL = "http://localhost:5002/api/reservations"

DEMO_USER = "john_user"
DEMO_PASS = "User@123"
RESOURCE_IDS = [1, 2, 3, 4, 5]

def authenticate_with_retry():
    while True:
        print(f"[*] Authenticating as {DEMO_USER}...")
        try:
            auth_response = requests.post(AUTH_URL, json={
                "username": DEMO_USER,
                "password": DEMO_PASS
            }, timeout=5)
            
            if auth_response.status_code == 200:
                print("[+] Authentication successful. Token acquired.\n")
                return auth_response.json().get("token")
            else:
                print(f"[!] Login failed (Status: {auth_response.status_code}). Response: {auth_response.text}")
                time.sleep(5)
                
        except (ConnectionError, ReadTimeout) as e:
            print(f"[!] Network error during auth ({type(e).__name__}). Retrying in 5 seconds...")
            time.sleep(5)

def generate_traffic():
    token = authenticate_with_retry()
    headers = {"Authorization": f"Bearer {token}"}

    print("[*] Starting reservation simulation (Press CTRL+C to stop)...")
    try:
        while True:
            resource_id = random.choice(RESOURCE_IDS)
            
            # THE FIX: Scatter the reservations randomly over the next 14 days
            # so the calendar doesn't instantly fill up today!
            days_in_future = random.randint(0, 14)
            start_dt = datetime.now(timezone.utc) + timedelta(days=days_in_future, hours=random.randint(0, 23))
            end_dt = start_dt + timedelta(hours=random.randint(1, 8))
            
            payload = {
                "resource_id": resource_id,
                "start_time": start_dt.isoformat(),
                "end_time": end_dt.isoformat()
            }
            
            try:
                res = requests.post(RESERVATION_URL, json=payload, headers=headers, timeout=5)
                
                # Format a nice date string for the console output
                date_str = start_dt.strftime("%Y-%m-%d")
                
                if res.status_code in [200, 201]:
                    print(f"[+] SUCCESS: Reserved ID {resource_id} for {date_str}")
                else:
                    print(f"[-] FAILED: Collision on ID {resource_id} for {date_str}")
                    
            except (ConnectionError, ReadTimeout):
                print("[!] Network timeout. Moving to next request...")
            
            # Wait 1 to 3 seconds between requests
            time.sleep(random.randint(1, 3))

    except KeyboardInterrupt:
        print("\n[*] Simulation stopped by user.")

if __name__ == "__main__":
    generate_traffic()