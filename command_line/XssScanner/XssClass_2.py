from urllib.parse import urljoin
import requests
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.common.by import By

driver = webdriver.Chrome()

class XssClass:
    @staticmethod
    def get_forms(url):
        html_content = ""
        response = requests.get(url)
        if response.status_code == 200:
            print("Website successfully reached")
            html_content = response.content
        elif response.status_code >= 400:
            print(f"Website not reached, not getting forms for {url}")
            return
        soup = BeautifulSoup(html_content, 'html.parser')
        forms = soup.find_all('form')
        return forms

    @staticmethod
    def get_form_details(form):
        action = form.attrs.get("action", "")
        method = form.attrs.get('method', 'GET')
        inputs = []
        input_options = form.find_all('input')
        for input_option in input_options:
            input_type = input_option.attrs.get('type','text')
            input_name = input_option.attrs.get('name','')
            inputs.append({'type': input_type.lower(), 'name': input_name})
        return action.lower(), method.lower(), inputs

    @staticmethod
    def submit_form(url, form, payloads):
        action, method, inputs = XssClass.get_form_details(form)
        target_endpoint = urljoin(url, action)
        data = {}
        for input in inputs:
            if input["type"] == "text" or input["type"] == "search":
                input["value"]   = payloads
            input_name = input.get("name")
            input_value = input.get("value")
            if input_name and input_value:
                data[input_name] = input_value
        if method == "post":
            print(f"Sending payload to inputs {data} using POST and http body")
            return requests.post(target_endpoint, data=data)
        else:
            print(f"Sending payload to inputs {data} using GET and http parameters")
            return requests.get(target_endpoint, params=data)

    @staticmethod
    def get_inputs(url):
        html_content = ""
        response = requests.get(url)
        if response.status_code == 200:
            print("Website successfully reached")
            html_content = response.content
        elif response.status_code >= 400:
            print(f"Website not reached, not getting forms for {url}")
            return
        soup = BeautifulSoup(html_content, 'html.parser')
        inputs = soup.find_all('inputs')
        return inputs

    @staticmethod
    def submit_input(input_names,url,payload):
        driver.get(url)
        for input_name in input_names:
            input_element=driver.find_element(By.NAME,input_name)
            input_element.send_keys(payload)
        driver.quit()


    @staticmethod
    def xss_scan(url):
        print(f"Starting XSS scan for {url}")
        forms = XssClass.get_forms(url)
        payload = "<script></script>"
        for form in forms:
            content = XssClass.submit_form(url, form, payload).content.decode()
            if payload in content:
                print("XSS Vulnerable")
            else:
                print("XSS Unvulnerable")


XssClass.xss_scan("https://xss-game.appspot.com/level1/frame")