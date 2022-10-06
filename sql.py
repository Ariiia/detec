from bs4 import BeautifulSoup as bs
import requests as req
from urllib.parse import urlparse 
from constants import REGEXP
import re

ses = req.Session()
ses.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
sql_warn = "Description: \tSQLi is highly dangerous for your database. You should use input validation, parameterized queries, stored procedures, and escaping to prevent it."
s = "`'\";"
def error_dbms(reply):
    for reg in REGEXP:
        result = re.search(reg, reply.text.lower())
        if result:
            return True
         
def sql_enter(url):
    
    info = scan_sql_injection(url, ses)
    
    if info == None:
        message = (f"...No SQL Injection was detected on {url}")
        info += message
    return info

def scan_sql_injection(url, ses):
    info = ''
    soup = bs(ses.get(url).content, 'html.parser')
    vuln_to_link  = False
    print(f"... Inserting to {url} >>")
    for symb in s:
        if vuln_to_link  == False:
            destination = url + symb
            
            vuln_to_link, info = verify_error_link(destination, vuln_to_link, info)
            if vuln_to_link == False:

                for symbol in range(len(url)):
                    if url[symbol].isdigit():
                        destination_after = url[:symbol+1] + symb + url[symbol+1:]
                        vuln_to_link, info = verify_error_link(destination_after, vuln_to_link, info)


            
    if "Injection found in the original link" not in info:
        message = (f"<< Link {url} is not injectable from link >>")
        info+=message
    forms = soup.find_all('form')

    if len(forms) == 0:
        info+=(f"\n<< No input forms were found on {url} >>\n")
        return info

    for form in forms:
        try:
            method = form.get('method').lower()
        except:
            #it is so by default
            method = 'get'
        try:
            action = form.get('action').lower()
        except:
            action = '/'  

        if action.startswith('http://') or  action.startswith('https://'):
            destination_url = action

        elif action == '#':
            #same page
            destination_url = url
        
        elif action == '' or action == None:
            destination_url = url

        elif action[0] == '/':
            #rel address
            psd = urlparse(url)
            domn, schema = psd.netloc, psd.scheme
            destination_url = schema +  "://" + domn + action

        else:
            action = '/' + action
            psd = urlparse(url)
            domn, schema = psd.netloc, psd.scheme
            destination_url = schema +  "://" + domn + action

        inputs = form.find_all('input')
        
        
        vulnerable = False
        for symb in s:
            if vulnerable == False:
                body = {}
                for input in inputs:
                    json_input = {}
                    try:
                        if input["name"]:

                            if input.get('type') == 'submit':
                                json_input[input["name"]] =  input.get("value")
                                
                            if input.get("type") == 'text' or not input.get("type"):
                                json_input[input.get("name")] = f"textDfield{symb}" 

                            if input.get("type") == 'password':
                                json_input[input.get("name")] = f"textDfield{symb}" #here insert
                    except:
                        continue
                    body |= json_input
                
                if (method == 'get'):
                    try:
                        reply = ses.get(destination_url, params = body)
                    except:
                        info+=(f"... Destinated link {destination_url} does not work")
                        return info
                else:
                    try:
                        reply = ses.post(destination_url, data = body)
                    except:
                        info+=(f"... Destinated link {destination_url} does not work")
                        return info

                if error_dbms(reply):
                    vulnerable = True
                    if sql_warn not in info:
                        info +="\n"+ sql_warn
                    print(f"... << Injection found in the input:\t{destination_url} >>")
                    info += f"\n<< Injection found in the input:\t {destination_url} >>\n"
                    info += (f"The affected form inputs: \n{form.find_all('input')}")
                    info += (f"\n<< Sent parameters in {method} request to the {action} >>:\n {body}\n")

    if "Injection found in the input" not in info:
        message = "\n<< Inputs were not found to be injectable >>\n"
        info += message
    return info


def verify_error_link(destination, vuln_to_link, info):
    reply = bs(ses.get(destination).content, 'html.parser')
    if error_dbms(reply):
        vuln_to_link = True
        if sql_warn not in info:
            info += sql_warn
        print(f"<< Injection found in the original link:\t{destination} >>")

        info += f"\n<< Injection found in the original link:\t {destination} >>"
    return vuln_to_link, info



if __name__ == '__main__':


    #url = 'http://testphp.vulnweb.com/artists.php?artist=1'
    url = 'http://testphp.vulnweb.com/artists.php?artist=1'
    soup = scan_sql_injection(url, ses)
    print(soup)
    psd = urlparse(url)
    print(psd)


