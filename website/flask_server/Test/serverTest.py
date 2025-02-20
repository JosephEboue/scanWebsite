import pytest
from flask import json
from ..server import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Test de la route principale
def test_hello_world(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Backend server is running' in response.data

# Test de la validation d'URL
@pytest.mark.parametrize("url,expected_status", [
    ("https://example.com", 200),
    ("invalid-url", 400),
    ("", 400),
])
def test_url_validation(client, url, expected_status):
    response = client.post('/xxe-scan', json={"url": url})
    assert response.status_code == expected_status

# Test de la route /scan-ip
def test_ip_scan(client, mocker):
    mock_ip_class = mocker.patch("WebsiteScanner.IpScanner.IpClass.check_ip", return_value={"ip": "127.0.0.1", "risk": "low"})
    response = client.post('/scan-ip', json={"ip_address": "127.0.0.1"})
    assert response.status_code == 200
    assert response.json == {"ip": "127.0.0.1", "risk": "low"}
    mock_ip_class.assert_called_once()

# Test de la route /xxe-scan
def test_xxe_scan(client, mocker):
    mock_xxe = mocker.patch("WebsiteScanner.XxeScanner.XxeVulnerabilityScanner.scan_xxe_vulnerability", return_value="No XXE vulnerability found")
    response = client.post('/xxe-scan', json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json == {"result": "No XXE vulnerability found"}
    mock_xxe.assert_called_once()

# Test de la route /fuzz
def test_fuzz_scan(client, mocker):
    mock_fuzzer = mocker.patch("WebsiteScanner.FuzzScanner.Fuzzer.simple_fuzz", return_value="Fuzz test passed")
    response = client.post('/fuzz', json={"url": "https://example.com", "fuzz_param": "id"})
    assert response.status_code == 200
    assert response.json == {"result": "Fuzz test passed"}
    mock_fuzzer.assert_called_once()

# Test de la route /sql-injection-scan
def test_sqli_scan(client, mocker):
    mock_sql = mocker.patch("WebsiteScanner.SqlScanner.SQLScanner.sql_injection_scan", return_value="No SQL injection found")
    response = client.post('/sql-injection-scan', json={"url": "https://example.com"})
    assert response.status_code == 200
    assert response.json == {"result": "No SQL injection found"}
    mock_sql.assert_called_once()

# Test de la route /all-scan
def test_all_scan(client, mocker):
    mock_xxe = mocker.patch("WebsiteScanner.XxeScanner.XxeVulnerabilityScanner.scan_xxe_vulnerability", return_value="No XXE")
    mock_fuzz = mocker.patch("WebsiteScanner.FuzzScanner.Fuzzer.simple_fuzz", return_value="No Fuzzing issue")
    mock_sqli = mocker.patch("WebsiteScanner.SqlScanner.SQLScanner.sql_injection_scan", return_value="No SQLi")
    
    response = client.post('/all-scan', json={"url": "https://example.com", "fuzz_param": "id"})
    assert response.status_code == 200
    assert response.json == {"result": {"XXE Scan": "No XXE", "Fuzz Scan": "No Fuzzing issue", "SQL Injection Scan": "No SQLi"}}
    
    mock_xxe.assert_called_once()
    mock_fuzz.assert_called_once()
    mock_sqli.assert_called_once()
