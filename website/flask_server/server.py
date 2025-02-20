import re
import threading
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from WebsiteScanner.IpScanner import IpClass
from WebsiteScanner.XxeScanner import XxeVulnerabilityScanner
from WebsiteScanner.FuzzScanner import Fuzzer
from WebsiteScanner.SqlScanner import SQLScanner

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

# IP validation regex pattern
IP_PATTERN = re.compile(
    r'^(?:\d{1,3}\.){3}\d{1,3}$'  # Matches IPv4 addresses
)

def is_valid_url(url):
    """ Validate if the given URL is properly formatted """
    return bool(URL_PATTERN.match(url))

def is_valid_ip(ip):
    """ Check if the input is a valid IP address """
    return bool(IP_PATTERN.match(ip))

def url_client_error(url):
    """ Validate URL input """
    if not url or not is_valid_url(url):
        return jsonify({"error": "Invalid URL provided"}), 400

@app.route('/all-scan', methods=['POST'])
def all_scan():
    try:
        data = request.json
        url = data.get('url')
        fuzz_param = data.get('fuzz_param')

        # Check if input is an IP address
        is_ip = is_valid_ip(url)

        # If it's neither a valid URL nor a valid IP, return an error
        if not is_ip and not is_valid_url(url):
            return jsonify({"error": "Invalid URL or IP address provided"}), 400

        results = {}
        lock = threading.Lock()

        def run_xxe():
            """ Run XXE Scan only for URLs """
            xxe_scanner = XxeVulnerabilityScanner(url)
            with lock:
                results["XXE Scan"] = xxe_scanner.scan_xxe_vulnerability()

        def run_fuzz():
            """ Run Fuzzing Scan """
            with lock:
                if fuzz_param:
                    fuzzer_scanner = Fuzzer(url, fuzz_param)
                    results["Fuzz Scan"] = fuzzer_scanner.simple_fuzz()
                else:
                    results["Fuzz Scan"] = "No fuzz parameter provided"

        def run_sqli():
            """ Run SQL Injection Scan """
            with lock:
                results["SQL Injection Scan"] = SQLScanner.sql_injection_scan(url, payload_file=PAYLOADS_FILE_PATH)

        def run_ip_scan():
            """ Run IP Scan if input is an IP address """
            ip_data = IpClass.check_ip(url, ABUSE_IPDB_API_KEY)
            with lock:
                if "error" in ip_data:
                    results["IP Scan"] = ip_data
                else:
                    results["IP Scan"] = IpClass.parse_ip_data(ip_data)

        # Create a list of scan threads
        threads = [
            threading.Thread(target=run_fuzz),
            threading.Thread(target=run_sqli),
        ]

        if is_ip:
            threads.append(threading.Thread(target=run_ip_scan))  # Run IP scan if input is an IP
        else:
            threads.append(threading.Thread(target=run_xxe))  # Run XXE scan only if input is a URL

        # Start and join threads
        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()

        return jsonify({"result": results}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
