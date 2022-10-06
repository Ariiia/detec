from urllib.parse import urlparse
import requests
import warnings
import builtins
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
import sys

def verify_link(url):
    try:
        
        result = urlparse(url)
        reply = requests.get(url, timeout=5, verify = False)
        if all([result.scheme, result.netloc, reply ]) and reply.status_code != 404:
            return True
        elif reply.status_code == 404:
            print("<< Link does not exist. 404 >>")
            sys.exit()
        else:
            print("<< Something went wrong >>")
            sys.exit()
    
    except Exception as e:
        if '[SSL: UNSUPPORTED_PROTOCOL]' in str(e):
            print("No support for TLS. Are you typing https instead of http?")
            
        elif ('getaddrinfo failed' in str(e)):
            print("Invalid link provided. Recheck and try again. This is probably not a problem with scheme")

        elif 'No connection could be made because the target machine actively refused it' in str(e):
            print('No connection could be made because the target machine actively refused it. Check if your server is up and running.')

        else:    
            print(e)
        
        sys.exit()



if __name__ == "__main__":
    print(verify_link("http://com"))
