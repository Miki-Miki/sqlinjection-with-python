import requests
import re
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from xml.dom import minidom

# initialize an HTTP session & set the browser
s = requests.Session()
# s.headers["User-Agent"] = "Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail appname/appversion"
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"


# initilizing sql response errors
xmlDoc = minidom.parse('errors.xml')
dbErrors = xmlDoc.getElementsByTagName('error')

DVWA_URL = 'http://localhost/dvwa/vulnerabilities/sqli/'
DVWA_LOGIN_URL = 'http://localhost/dvwa/login.php'

# logging in
login_payload = {
    "username": "admin",
    "password": "password",
    "Login": "Login",
}
r = s.get(DVWA_LOGIN_URL)
token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
login_payload['user_token'] = token
s.post(DVWA_LOGIN_URL, data=login_payload)


def get_all_forms(url):
    soup = bs(s.get(url).content, 'html.parser')
    return soup.find_all('form')

def get_form_details(form):
    details = {}
    # get the form action (target url)
    try:
        action = form.attrs.get("action").lower()
    except:
        action = None
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # method = form['method'].lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def is_vulnerable(response):
    errors = []

    for items in dbErrors: 
        errors.append(items.attributes['regexp'].value)

    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True

    # no error detected
    return False

def scan_sql_injection(url):

    # test on HTML forms
    forms = get_all_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    # test on URL
    for c in "\"'":
        # add quote/double quote character to the URL
        new_url = f"{url}{c}"
        print("[!] Trying", new_url)

        # make the HTTP request
        res = s.get(new_url)
        if is_vulnerable(res):
            # SQL Injection detected on the URL itself, 
            # no need to preceed for extracting forms and submitting them
            print("[+] SQL Injection vulnerability detected, link:", new_url)
            return

    for form in forms:
        form_details = get_form_details(form)
        #print(form_details)

        for c in "\"'":
            # the data body we want to submit
            data = {}

            for input_tag in form_details["inputs"]:
                if (input_tag["type"] == "hidden" or input_tag["value"] or input_tag["value"] == '') and input_tag["type"] != 'submit':
                    # any input form that is hidden or has some value,
                    # just use it in the form body
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    # all others except submit, use some junk data with special character
                    data[input_tag["name"]] = f"test{c}"

                if input_tag["type"] == "submit":
                    data[input_tag["name"]] = input_tag["value"]


            # join the url with the action (form request URL)
            url = urljoin(url, form_details["action"])

            form_response = ''

            if form_details["method"] == "post":
                form_response = s.post(url, data=data)
                #print(res.content.decode())
            elif form_details["method"] == "get":
                form_response = s.get(url, params=data)
                #print(form_response.content.decode().lower())

            # test whether the resulting page is vulnerable
            if is_vulnerable(form_response):
                print("[+] SQL Injection vulnerability detected, link:", url)
                print("[+] Form:")
                pprint(form_details)
                break

if __name__ == "__main__":    
    scan_sql_injection(DVWA_URL)
