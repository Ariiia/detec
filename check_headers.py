import requests
from db_connection import lut_collection as collection
from constants import HEADERS
import sys  

def check_header(h, state, info):
    if h == "Content-Security-Policy":
        #ok if present
        state[h]["present"] = 1
        state[h]["ok"] = 1

    if h == "X-Frame-Options":
        state[h]["present"] = 1
        if info[h].lower() == 'sameorigin' or info[h].lower() == 'deny':
            state[h]["ok"] = 1

    if h == "Strict-Transport-Security":
        #note that google may sometimes not include hsts 
        state[h]["present"] = 1
        #at least 1 year (31536000)
        parse = info[h].lower().split("; ")
        for e in parse:
            if "max-age" in e:
                res = int(e.partition("=")[2])
                if res >= 31536000:
                    state[h]["ok"] = 1
    
    if h == "Permissions-Policy":
        #warn to switch to it
        state[h]["present"] = 1
        state[h]["ok"] = 1

    if h == "Feature-Policy":
        #ok = 0 by default
        state[h]["present"] = 1
        state[h]["ok"] = 0
    
    if h == "Referrer-Policy":
        state[h]["present"] = 1
        ref_values = ["no-referrer-when-downgrade", "origin-when-cross-origin", "strict-origin-when-cross-origin",
        "no-referrer", "strict-origin", "same-origin"]
        for e in ref_values:
            if e in info[h].lower():
                state[h]["ok"] = 1

    if h == "X-Content-Type-Options":
        state[h]["present"] = 1
        if info[h].lower() == "nosniff":
            state[h]["ok"] = 1

def enter_headers(url):
    session = requests.Session()
    session.headers.update({
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0",
        'Cache-control': 'no-cache',
        'Pragma': 'no-cache',
        'Connection': 'close'
    })
    info = session.get(url, verify = True, timeout = 5).headers

    state = {"Content-Security-Policy": {"present": 0, "ok": 0}, 
                "X-Frame-Options": {"present": 0, "ok": 0},
                "Strict-Transport-Security": {"present": 0, "ok": 0},
                "Permissions-Policy": {"present": 0, "ok": 0}, 
                "Feature-Policy": {"present": 0, "ok": 0}, 
                "Referrer-Policy": {"present": 0, "ok": 0},
                "X-Content-Type-Options": {"present": 0, "ok": 0}}   

    try:
        for each in info:
            if each in HEADERS:
                check_header(each, state, info)

    except Exception as e:
        print("checkHeaders Exception"+ str(e))

    res_str = decipher_headers(state)

    return res_str

def decipher_headers(state):

    result = ''
    
    headers_ok = True
    for HEADER in HEADERS:
        if (state[HEADER]['ok'] == 0):
            headers_ok = False
            try:
                record = collection.find_one({"name": HEADER})
            except Exception as e:
                print(str(e))
                sys.exit()
            result += ' Header: \t ' + record['name'] + ' is advised to be set or configured properly\n'
            result += ' Description: \n\t ' + record['description'] + '\n'
            result += ' Recommendation: \n\t ' + record['recommendation'] + '\n\n'

    if headers_ok:
        result += 'No problems found in security headers. Very good!\n'

    return result



if __name__ == "__main__":
    url = "https://google.com/"
    res_str = enter_headers(url)
    print(res_str)
    
        




