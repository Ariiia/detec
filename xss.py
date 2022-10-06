from bs4 import BeautifulSoup as bs
import requests as req
from urllib.parse import urlparse 
from constants import XSS_PAYLOADS

ses = req.Session()
ses.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
xss_warn = "Description: \t XSS is based on input of malicious JavaScript code. You should filter and all the input data, make a list of allowed inputs as well as set security headers properly \n"

                
def xss_enter(url):
    
    info = scan_xss(url, ses)
    
    if info == None:
        message = (f"...No XSS was detected on {url}")
        info += message
    return info

def scan_xss(url, ses):
    info = ''
    soup = bs(ses.get(url).content, 'html.parser')
    
    forms = soup.find_all('form')
    if len(forms) == 0:
        message = (f"... No input forms were found on {url} to scan for XSS\n")
        info += message
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

        if action.startswith('http://') or action.startswith('https://'):
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

        # with open("xss_payloads.txt") as file:
        #     lines = file.readlines()
        vulnerable = False
        for each_script in XSS_PAYLOADS:
            if vulnerable == True:
                continue
            else:
                body = {}
                for input in inputs:
                    json_input = {}
                    try:
                        if input["name"]:
                            if input.get("type") == 'submit':
                                json_input[input["name"]] =  input.get("value")
                                
                            if input.get("type") == 'text' or not input.get("type") or input.get("type") == 'hidden':
                                json_input[input.get("name")] = f"textDfield{each_script}" 

                            if input.get("type") == 'password':
                                json_input[input.get("name")] = f"textDfield{each_script}" #here insert
                    except Exception as e:
                        continue
                        
                    body |= json_input
                if (method == 'get'):
                    try:
                        reply = ses.get(destination_url, params = body)
                    except:
                        print(f"... Link {destination_url} does not work")
                        return info
                else:
                    try:
                        reply = ses.post(destination_url, data = body)
                    except:
                        print(f"... Link {destination_url} does not work")
                        return info

                if each_script in reply.text:
                    vulnerable = True
                    if xss_warn not in info:
                        info += xss_warn
                    print(f"... XSS spotted in the input:\t from {url} to {destination_url}")
                    info += f"<< XSS spotted in the input:\t {url} to {destination_url} >>\n"
                    info += (f"The affected form inputs: \n{form.find_all('input')}\n")
                    info += (f"<< Sent parameters in {method} request to the {action} >>:\n {body}\n")
    if not xss_warn in info:
        info += f"<< No xss was found on {url} >>\n"
    return info
            


if __name__ == '__main__':

    url = 'https://xss-game.appspot.com/level1/frame'
    scan = scan_xss(url, ses)
