import requests

class IpClass:

    @staticmethod
    def check_ip(ip_address, api_key):
        # Vérifier l'adresse IP avec l'API AbuseIPDB."""
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': api_key,
            'Accept': 'application/json'
        }
        params = {
            'ipAddress': ip_address,
            'verbose': True,
            'maxAgeInDays': 90  
        }

        print("apiKey:",api_key)
        try:
            # Envoyer la requête à AbuseIPDB
            response = requests.get(url, headers=headers, params=params)
            # Vérification du succès de la requête
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": "Failed to retrieve data from AbuseIPDB"}
        except requests.exceptions.RequestException as e:
            return {"error": f"Request error: {str(e)}"}

    @staticmethod
    def parse_ip_data(ip_data):
        # Extraction des informations pertinentes du résultat de l'API.
        if "data" not in ip_data:
            return {"error": "No data found for this IP"}
        
        data = ip_data["data"]
        parsed_data = {
            "ipAddress": data.get("ipAddress", "N/A"),
            "domain": data.get("domain", "N/A"),
            "abuseConfidenceScore": data.get("abuseConfidenceScore", "N/A"),
            "countryName": data.get("countryName", "N/A"),
            "totalReports": data.get("totalReports", "N/A"),
            "lastReportedAt": data.get("lastReportedAt", "N/A"),
            "isWhitelisted": data.get("isWhitelisted", False),
            "reporterCountryName": data.get("reporterCountryName", "N/A"),
        }
        return parsed_data
