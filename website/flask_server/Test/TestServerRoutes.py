import sys
import os
import pytest
from flask import json
from urllib.parse import urlparse
from unittest import mock
from dotenv import load_dotenv
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

    # Test de la route principale
    def test_hello_world(self, client):
        response = client.get('/')
        assert response.status_code == 200
        assert b'Backend server is running' in response.data

    # Test de la validation d'URL
    # @pytest.mark.parametrize("url,expected_status", [
    #     ("https://example.com", 200),
    #     ("invalid-url", 400),
    #     ("", 400),
    # ])
    # def test_url_validation(self, client, url, expected_status):
    #     response = client.post('/xxe-scan', json={"url": url})
    #     assert response.status_code == expected_status

    # Test de la route /scan-ip
    def test_ip_scan(self, client, mocker):

            # Mocker la méthode check_ip pour renvoyer des données factices
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

            # Effectuer la requête POST avec l'IP à tester
            response = client.post('/scan-ip', json={"ip_address": "186.23.212.74"})
            
            # Vérifier que la réponse a le bon statut et que les données retournées correspondent aux valeurs simulées
            assert response.status_code == 200
            assert response.json == {
                "ipAddress": "186.23.212.74",
                "domain": "telecentro.com.ar",
                "abuseConfidenceScore": 100,
                "countryName": "N/A",
                "totalReports": 2689,
                "lastReportedAt": "2025-02-20T16:47:46+00:00",
                "isWhitelisted": False,
                "reporterCountryName": "N/A"
            }
            
            # Vérifier que la méthode check_ip a été appelée une fois avec l'IP correcte et la clé API factice
            mock_ip_class.assert_called_once_with("186.23.212.74", ABUSE_IPDB_API_KEY)

    # Test de la route /xxe-scan
    def test_xxe_scan(self, client, mocker):
        # Mocker pour simuler la réponse de la fonction scan_xxe_vulnerability
        mock_xxe = mocker.patch("WebsiteScanner.XxeScanner.XxeVulnerabilityScanner.scan_xxe_vulnerability", return_value="No XXE vulnerability found")
        response = client.post('/xxe-scan', json={"url": "https://example.com"})
        assert response.status_code == 200
        assert response.json == {"result": "No XXE vulnerability found"}
        mock_xxe.assert_called_once()

    # Test de la route /fuzz
    def test_fuzz_scan(self, client, mocker):
        # Mocker pour simuler la réponse de la fonction simple_fuzz
        mock_fuzzer = mocker.patch("WebsiteScanner.FuzzScanner.Fuzzer.simple_fuzz", return_value="Fuzz test passed")
        response = client.post('/fuzz', json={"url": "https://example.com", "fuzz_param": "id"})
        assert response.status_code == 200
        assert response.json == {"result": "Fuzz test passed"}
        mock_fuzzer.assert_called_once()

    # Test de la route /sql-injection-scan
    def test_sqli_scan(self, client, mocker):
        # Mocker pour simuler la réponse de la fonction sql_injection_scan
        mock_sql = mocker.patch("WebsiteScanner.SqlScanner.SQLScanner.sql_injection_scan", return_value="No SQL injection found")
        response = client.post('/sql-injection-scan', json={"url": "https://example.com"})
        assert response.status_code == 200
        assert response.json == {"result": "No SQL injection found"}
        mock_sql.assert_called_once()

    # Test de la route /all-scan
    def test_all_scan(self, client, mocker):
        # Mocker pour chaque scanner utilisé dans le scan global
        mock_xxe = mocker.patch("WebsiteScanner.XxeScanner.XxeVulnerabilityScanner.scan_xxe_vulnerability", return_value="No XXE")
        mock_fuzz = mocker.patch("WebsiteScanner.FuzzScanner.Fuzzer.simple_fuzz", return_value="No Fuzzing issue")
        mock_sqli = mocker.patch("WebsiteScanner.SqlScanner.SQLScanner.sql_injection_scan", return_value="No SQLi")
        
        response = client.post('/all-scan', json={"url": "https://example.com", "fuzz_param": "id"})
        assert response.status_code == 200
        assert response.json == {"result": {"XXE Scan": "No XXE", "Fuzz Scan": "No Fuzzing issue", "SQL Injection Scan": "No SQLi"}}
        
        mock_xxe.assert_called_once()
        mock_fuzz.assert_called_once()
        mock_sqli.assert_called_once()
