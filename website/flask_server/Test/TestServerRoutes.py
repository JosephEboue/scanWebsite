import sys
import os
import pytest
from flask import json
from dotenv import load_dotenv
from unittest import mock

# Ajout du dossier contenant `server.py` au sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'flask_server')))

load_dotenv()
ABUSE_IPDB_API_KEY = os.getenv("ABUSE_IPDB_API_KEY")

from server import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

class TestServerRoutes:

    # Test de la route /all-scan avec une URL valide
    def test_all_scan_url(self, client, mocker):
        # Mock des résultats attendus
        mock_xxe = mocker.patch("WebsiteScanner.XxeScanner.XxeVulnerabilityScanner.scan_xxe_vulnerability", return_value="No XXE vulnerability found")
        mock_fuzz = mocker.patch("WebsiteScanner.FuzzScanner.Fuzzer.simple_fuzz", return_value="No Fuzzing issue")
        mock_sqli = mocker.patch("WebsiteScanner.SqlScanner.SQLScanner.sql_injection_scan", return_value="No SQL injection found")

        response = client.post('/all-scan', json={"url": "https://example.com", "fuzz_param": "id"})
        
        assert response.status_code == 200
        assert response.json == {
            "result": {
                "XXE Scan": "No XXE vulnerability found",
                "Fuzz Scan": "No Fuzzing issue",
                "SQL Injection Scan": "No SQL injection found"
            }
        }
        
        mock_xxe.assert_called_once()
        mock_fuzz.assert_called_once()
        mock_sqli.assert_called_once()

    # Test de la route /all-scan avec une IP
    def test_all_scan_ip(self, client, mocker):
        # Mock du retour attendu
        mock_ip_class = mocker.patch("WebsiteScanner.IpScanner.IpClass.check_ip", return_value={
            "data": {
                "abuseConfidenceScore": 100,
                "countryName": "N/A",
                "domain": "telecentro.com.ar",
                "ipAddress": "186.23.212.74",
                "isWhitelisted": False,
                "lastReportedAt": "2025-02-20T16:47:46+00:00",
                "reporterCountryName": "N/A",
                "totalReports": 2689
            }
        })

        response = client.post('/all-scan', json={"url": "186.23.212.74"})

        expected_result = {
            "result": {
                "IP Scan": {
                    "ipAddress": "186.23.212.74",
                    "domain": "telecentro.com.ar",
                    "abuseConfidenceScore": 100,
                    "countryName": "N/A",
                    "totalReports": 2689,
                    "lastReportedAt": "2025-02-20T16:47:46+00:00",
                    "isWhitelisted": False,
                    "reporterCountryName": "N/A"
                },
                "Fuzz Scan": "No fuzz parameter provided"  # Ajout de cette ligne pour correspondre à la réponse réelle
            }
        }

        assert response.status_code == 200
        assert response.json == expected_result

    # Test d'erreur avec une URL invalide
    @pytest.mark.parametrize("invalid_url", ["invalid-url", "", "htp://badurl"])
    def test_all_scan_invalid_url(self, client, invalid_url):
        response = client.post('/all-scan', json={"url": invalid_url})
        assert response.status_code == 400
        assert response.json == {"error": "Invalid URL or IP address provided"}

