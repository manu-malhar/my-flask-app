from flask import Flask, request, jsonify
import requests
import re
import time
import json
import os

app = Flask(__name__)

CACHE_FILE = "virus_total_cache.json"
CACHE_EXPIRY_SECONDS = 86400  # 24 hours

def get_ip_address():
    """Get the IP address of the current machine"""
    try:
        # Create a socket connection to a remote address to determine our IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "0.0.0.0"


API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
if not API_KEY:
    raise ValueError("No VIRUSTOTAL_API_KEY set for application")
BASE_URL = "https://www.virustotal.com/api/v3/"

# Load cache from file (if exists)
def load_cache():
    if not os.path.exists(CACHE_FILE):
        # Create an empty file if it doesn't exist
        with open(CACHE_FILE, "w") as f:
            json.dump({}, f)
    
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}

# Save cache to file
def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)

cache = load_cache()  # Initialize cache

def is_valid_domain(input_str):
    return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", input_str)

def get_cache_key(target):
    """Generate a consistent cache key for the target"""
    return f"vt_{target}"

def check_malicious_cached(target):
    """Check VirusTotal with file-based caching"""
    cache_key = get_cache_key(target)
    
    # Return cached result if available and not expired
    cached_data = cache.get(cache_key)
    if cached_data and (time.time() - cached_data['timestamp']) < CACHE_EXPIRY_SECONDS:
        return cached_data['result'], cached_data['details'], True  # True = is_cached
    
    # If not in cache or expired, call VirusTotal API
    try:
        if len(target) == 64 and re.match(r"^[a-fA-F0-9]{64}$", target):
            endpoint = f"files/{target}"
        elif is_valid_domain(target):
            endpoint = f"domains/{target}"
        else:
            return None, "Invalid input type", False

        headers = {"x-apikey": API_KEY}
        response = requests.get(BASE_URL + endpoint, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            result = (stats["malicious"] > 0 or stats["suspicious"] > 0)
            
            # Store in cache and save to file
            cache[cache_key] = {
                'result': result,
                'details': data,
                'timestamp': time.time()
            }
            save_cache(cache)  # Persist to disk
            return result, data, False  # False = not from cache
        return None, f"API Error: {response.status_code}", False
    except Exception as e:
        return None, f"Request Failed: {str(e)}", False

@app.route('/api/data', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        app_name = data['appName']
        package_name = data['packageName']
        permissions = data.get('permissions', [])
        sha256 = data.get('sha256')
        
        if sha256:
            result, details, is_cached = check_malicious_cached(sha256)
            scan_type = "SHA-256"
            target = sha256
        else:
            parts = package_name.split('.')
            domain = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else package_name
            result, details, is_cached = check_malicious_cached(domain)
            scan_type = "domain"
            target = domain

        if result is None:
            return jsonify({
                "status": "error",
                "message": details,
                "domain": target if scan_type == "domain" else None,
                "sha256": target if scan_type == "SHA-256" else None,
                "is_malicious": None,
                "scan_stats": None
            }), 400

        scan_stats = details['data']['attributes']['last_analysis_stats']
        response_data = {
            "status": "success",
            "message": "Scan completed",
            "appName": app_name,
            "packageName": package_name,
            "scan_type": scan_type,
            "target": target,
            "is_malicious": bool(result),
            "scan_stats": scan_stats,
            "permissions": permissions,
            "cached": is_cached  # Indicates if result was from cache
        }

        return jsonify(response_data), 200
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 400

@app.route('/clear-cache', methods=['POST'])
def clear_cache():
    try:
        global cache
        cache = {}
        save_cache(cache)  # Clear the file
        return jsonify({"status": "success", "message": "Cache cleared"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/')
def home():
    import socket
    hostname = socket.gethostname()
    ip_address = get_ip_address()
    
    return f"""
    <h1>Flask Server is Running in Docker on GitHub Codespaces</h1>
    <p>Hostname: {hostname}</p>
    <p>IP Address: {ip_address}</p>
    <p>Available endpoints:</p>
    <ul>
        <li>POST /api/data - Scan app by SHA-256 or package name</li>
        <li>POST /clear-cache - Clear the cache</li>
    </ul>
    <p>Cache size: {len(cache)} entries</p>
    <p>Cache file: {CACHE_FILE}</p>
    <p>Running in Docker container</p>
    """

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)