import requests
import re
import sys
import validators
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
from pprint import pprint
from xml.dom import minidom

# initialize an HTTP session
s = requests.Session()

# s.headers["User-Agent"] = "Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail appname/appversion"
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

# initilizing sql response errors
xmlDoc = minidom.parse('errors.xml')
dbErrors = xmlDoc.getElementsByTagName('error')

# URL = 'http://localhost/dvwa/vulnerabilities/sqli/'
if len(sys.argv) == 1:
    print('[!] No option or URL provided. Exiting.')
    exit()

URL = sys.argv[1]

#DVWA_LOGIN_URL = 'http://localhost/dvwa/login.php'
LOGIN_URL = ''

# logging in
login_payload = {
    "username": "admin",
    "password": "password",
    "Login": "Login",
}

# r = s.get(LOGIN_URL)
# token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
# login_payload['user_token'] = token
# s.post(LOGIN_URL, data=login_payload)

class HTMLForms:
    @staticmethod
    def get_all_forms(url):
            soup = bs(s.get(url).content, 'html.parser')
            return soup.find_all('form')
    
    @staticmethod
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

class LoginAuthorization:
    def __init__(self, login_url):
        login_url_validation = validators.url(login_url)

        if login_url == '':
            self.login = login_url
        elif not login_url_validation:
            print('[!] Provided login URL is invalid. Exiting.')
            exit()

        self.login_url = login_url

    @staticmethod
    def get_login_information(self):
        if self.login_url == '':
            return True

        login_forms = HTMLForms.get_all_forms(self.login_url)
        login_forms_details = {}
        username_input = False
        password_input = False

        for form in login_forms:
            login_forms_details = HTMLForms.get_form_details(form)

            for input_tag in login_forms_details["inputs"]:
                if input_tag['name'] == 'username':
                    username_input = True
                    print('-- username input detected')
                    username = input('Username: ')

                if input_tag['name'] == 'password':
                    password_input = True
                    print('-- password input detected')
                    password = input('Password: ')

        login_payload['username'] = username
        login_payload['password'] = password

        r = s.get(self.login_url)
        token = re.search("user_token'\s*value='(.*?)'", r.text).group(1)
        login_payload['user_token'] = token
        login_res = s.post(self.login_url, data=login_payload)
        #print('LOGIN_URL: ' + LOGIN_URL)
        
        if login_res.url == self.login_url:
            print('[!] Login failed.')
            print('[-] Continuing ...')
            login_failure = True
            return True

        print('[+] Login successful!')
        return True


class SQLiTest:
    # url = sys.argv[1]
    def __init__(self, url, login_authorization = False):
        self.url = url
        login_url = input('Provide login URL (if not required leave empty): ')
        authorization_obj = LoginAuthorization(login_url)
        self.login_authorization = authorization_obj.get_login_information(authorization_obj)

    def is_vulnerable(self, response):
        errors = []

        for items in dbErrors: 
            errors.append(items.attributes['regexp'].value)

        for error in errors:
            # if you find one of these errors, return True
            if error in response.content.decode().lower():
                return True

        # no error detected
        return False

    def scan_sql_injection(self):
        # test on HTML forms
        forms = HTMLForms.get_all_forms(self.url)
        print(f"[+] Detected {len(forms)} forms on {self.url}.")

        # test on URL
        for c in "\"'":
            # add quote/double quote character to the URL
            new_url = f"{self.url}{c}"
            print("[!] Trying", new_url)

            # make the HTTP request
            res = s.get(new_url)
            if self.is_vulnerable(res):
                # SQL Injection detected on the URL itself, 
                # no need to preceed for extracting forms and submitting them
                print("[+] SQL Injection vulnerability detected, link:", new_url)
                return

        for form in forms:
            form_details = HTMLForms.get_form_details(form)
            #print(form_details)

            for c in "\"'":
                # the data body we want to submit
                data = {}

                for input_tag in form_details["inputs"]:
                    if input_tag["type"] == "hidden" or input_tag["value"]:
                        # any input form that is hidden or has some value,
                        # just use it in the form body
                        try:
                            data[input_tag["name"]] = input_tag["value"] + c
                        except:
                            pass
                    elif input_tag["type"] != "submit":
                        # all others except submit, use some junk data with special character
                        data[input_tag["name"]] = f"test{c}"


                # join the url with the action (form request URL)
                url = urljoin(self.url, form_details["action"])

                if form_details["method"] == "post":
                    form_res = s.post(url, data=data)
                elif form_details["method"] == "get":
                    form_res = s.get(url, params=data)

                # test whether the resulting page is vulnerable
                if self.is_vulnerable(form_res):
                    print("[+] SQL Injection vulnerability detected, link:", url)
                    print("[+] Form:")
                    pprint(form_details)
                    break

if sys.argv[1] == '-h' or sys.argv[1] == '--help':
    print('')
    print('python sqlInjectionScanner.py - scans the website of a given URL for SQLi vulnerabilities.')
    print('')
    print('Synopsis')
    print('\tpython sqlInjectionScanner.py [OPTION] | URL')
    print('')
    print('Options')
    print('-h --help\n\tHelp: Show syntax')
    print('')
    print('Arguments')
    print('URL\n\tThe URL of the website on which to perform SQLi vulnerability scan')

elif __name__ == "__main__":  
    sqli_test = SQLiTest(URL)
    login_res = sqli_test.login_authorization
    if login_res == True: 
        print('MAIN_URL: ' + URL)
        sqli_test.scan_sql_injection()
