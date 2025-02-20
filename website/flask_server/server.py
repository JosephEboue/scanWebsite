import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import re
from WebsiteScanner.IpScanner import IpClass
from WebsiteScanner.XxeScanner import XxeVulnerabilityScanner
from WebsiteScanner.FuzzScanner import Fuzzer
from WebsiteScanner.SqlScanner import SQLScanner
from dotenv import load_dotenv

app = Flask(__name__)
CORS(app)
# Define payload file paths
WEBSITE_SCANNER_DIRECTORY = os.path.abspath(os.path.dirname(__file__))
PAYLOADS_FILE_PATH = os.path.join(WEBSITE_SCANNER_DIRECTORY, 'WebsiteScanner/payloads.txt')

load_dotenv()
ABUSE_IPDB_API_KEY = os.getenv("ABUSE_IPDB_API_KEY")

# URL validation regex pattern
URL_PATTERN = re.compile(
    r'^(https?://)?'  
    r'([a-zA-Z0-9.-]+(\.[a-zA-Z]{2,})+)'  
    r'(:\d{1,5})?'  
    r'(/.*)?$' 
)
def is_valid_url(url):
    #Validate if the given URL is properly formatted
    return bool(URL_PATTERN.match(url))
def url_client_error(url):
    if not url or not is_valid_url(url):
        return jsonify({"error": "Invalid URL provided"}), 400
    
@app.route('/')
def hello_world():
    return 'Backend server is running'

@app.route('/scan-ip', methods=['POST'])
def ip_scan():
    try:
        data = request.json
        ip_address = data.get('ip_address')
        if not ip_address:
            return jsonify({"error": "IP address is required"}), 400
        
         # Utiliser la classe IpScanner pour vérifier l'IP
        ip_data = IpClass.check_ip(ip_address, ABUSE_IPDB_API_KEY)

        if "error" in ip_data:
            return jsonify(ip_data), 500

        # Extraire et retourner les données pertinentes
        parsed_data = IpClass.parse_ip_data(ip_data)
        return jsonify(parsed_data), 200

    except Exception as e:
        app.logger.error(f"Error in IP scan: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/xxe-scan', methods=['POST'])
def xxe_scan():
    try:
        data = request.json
        url = data.get('url')
        url_client_error(url)
        xxe_scanner = XxeVulnerabilityScanner(url)
        result = xxe_scanner.scan_xxe_vulnerability()
        return jsonify({"result": result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/fuzz', methods=['POST'])
def fuzz_scan():
    try:
        data = request.json
        url = data.get('url')
        fuzz_param = data.get('fuzz_param')
        url_client_error(url)
        if not fuzz_param:
            return jsonify({"error": "Missing fuzz parameter"}), 400

        fuzzer_scanner = Fuzzer(url, fuzz_param)
        result = fuzzer_scanner.simple_fuzz()
        return jsonify({"result": result}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/sql-injection-scan', methods=['POST'])
def sqli_scan():
    try:
        data = request.json
        url = data.get('url')
        url_client_error(url)
        result = SQLScanner.sql_injection_scan(url, payload_file=PAYLOADS_FILE_PATH)
        return jsonify({"result": result}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500    

@app.route('/all-scan', methods=['POST'])
def all_scan():
    try:
        data = request.json
        url = data.get('url')
        url_client_error(url)
        fuzz_param = data.get('fuzz_param')
        # Run all scans asynchronously
        results = {}
        # Pour assurer l'accès thread-safe à results
        lock = threading.Lock()
        def run_xxe():
            xxe_scanner = XxeVulnerabilityScanner(url)
            with lock:
                results["XXE Scan"] = xxe_scanner.scan_xxe_vulnerability()

        def run_fuzz():
            with lock:
                if fuzz_param:
                    fuzzer_scanner = Fuzzer(url, fuzz_param)
                    results["Fuzz Scan"] = fuzzer_scanner.simple_fuzz()
                else:
                    results["Fuzz Scan"] = "No fuzz parameter provided"

        def run_sqli():
            with lock:
                results["SQL Injection Scan"] = SQLScanner.sql_injection_scan(url, payload_file=PAYLOADS_FILE_PATH)

        # Create threads for parallel execution
        threads = [
            threading.Thread(target=run_xxe),
            threading.Thread(target=run_fuzz),
            threading.Thread(target=run_sqli),
        ]

        # Start threads
        for thread in threads:
            thread.start()
        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        return jsonify({"result": results}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

if __name__ == '__main__':
    app.run(debug=True)
