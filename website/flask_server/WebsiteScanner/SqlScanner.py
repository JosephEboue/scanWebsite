import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

s = requests.Session()
class SQLScanner:
    @staticmethod
    def get_forms(url):
        soup = BeautifulSoup(s.get(url).content, "html.parser")
        return soup.find_all("form")

    @staticmethod
    def form_details(form):
        detailsOfForm = {}
        action = form.attrs.get("action")
        method = form.attrs.get("method", "get")
        inputs = []

        for input_tag in form.find_all("input"):
            input_type = input_tag.attrs.get("type", "text")
            input_name = input_tag.attrs.get("name")
            input_value = input_tag.attrs.get("value", "")
            inputs.append({
                "type": input_type, 
                "name" : input_name,
                "value" : input_value,
            })
            
        detailsOfForm['action'] = action
        detailsOfForm['method'] = method
        detailsOfForm['inputs'] = inputs
        return detailsOfForm

    @staticmethod
    def vulnerable(response):
        errors = {"quoted string not properly terminated", 
                "unclosed quotation mark after the charachter string",
                "you have an error in you SQL syntax",
                "SQL syntax error",
                }
        for error in errors:
            if error in response.content.decode().lower():
                return True
        return False

    @staticmethod
    def submit_form(action, method, inputs):
        
        data = {input_field['name']: input_field['value'] for input_field in inputs if input_field['type'] != 'submit'}
        
        try:
            if method == 'post':
                response = requests.post(action, data=data)
            elif method == 'get':
                response = requests.get(action, params=data)
            else:
                print(f"Unsupported HTTP method: {method}")
                return None

            return response

        except Exception as e:
            print(f"Error submitting form: {e}")
            return None

    @staticmethod
    def sql_injection_scan(url, payload_file):
        vulnerable = False
        
        forms = SQLScanner.get_forms(url)

        with open(payload_file, 'r') as file:
            payloads = [line.strip() for line in file]

        for form in forms:
            details = SQLScanner.form_details(form)
            details['action'] = urljoin(url, details['action'])

            for input_field in details['inputs']:
                if input_field['type'] != "submit":
                    for payload in payloads:
                        input_field['value'] = payload
                        response = SQLScanner.submit_form(details['action'], details['method'], details['inputs'])

                        if SQLScanner.vulnerable(response):
                            vulnerable = True
                    else:
                        continue
        
        if not vulnerable:
            return "Possible vulnerability found"
        else:
            return "No vulnerability found"