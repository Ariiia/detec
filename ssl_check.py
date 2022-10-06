import requests as req
import ssl
import OpenSSL
from urllib.parse import urlparse
from datetime import datetime
#works fine with unknown certs
import sys

#date of cert
def ssl_date(hostname, port, info):
    pem_cert = ssl.get_server_certificate((hostname, port))
    reformat = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)
    start_date = reformat.get_notBefore()
    
    end_date = reformat.get_notAfter()
    decoded_start = decode_cert_date(start_date)
    decoded_end = decode_cert_date(end_date)
    
    info+="Certificate is valid from " + str(decoded_start) +" till " + str(decoded_end)+"\n"
    
    return info

def decode_cert_date(date):
    return  datetime.strptime(date.decode('ascii'), '%Y%m%d%H%M%SZ').strftime("%Y-%m-%d %H:%M:%S GMT")   

def ssl_enter(url):
    info = ""
    parsed = urlparse(url)

    schema = parsed[0]
    hostname = parsed[1]
    
    #trying https
    link = "https://" + hostname

    try:
        reply = req.get(link, timeout = 3, verify = True)
    
    except ssl.SSLCertVerificationError as e:
        message = str(e)
        print(message+"!!!")
        info += message
        return info
    
    except req.exceptions.ConnectTimeout as e:
        #https://rozklad.kpi.ua/Schedules/ViewSchedule.aspx?g=765dc2ee-edcf-4f57-abfb-766ebc3baa1f
        message = "Server did not respond to https. Server has 443 port probably closed and serves over http only. Thus no ssl certificate was found."
        print(message)
        info += message
        return info
    
    except req.exceptions.ConnectionError as e:
        if ('[SSL: UNSUPPORTED_PROTOCOL]' in str(e)):
            #http://rozklad.kpi.ua/Schedules/ViewSchedule.aspx?g=765dc2ee-edcf-4f57-abfb-766ebc3baa1f
            info += 'Could not verify SSL certificate because this site does not support modern TLS protocol'
            return info
        
        if '[SSL: WRONG_VERSION_NUMBER]' in str(e):
            #http://127.0.0.1:5000/
            info += 'Could not verify SSL certificate because TLS is probably disabled for this server and certificates are not set up'
            return info

        if 'certificate verify failed: certificate has expired' in str(e):
            #works with 'https://expired.badssl.com'

            info += ssl_date(hostname, 443, info)
            info += " Certificate has expired \n"
            return info

        if 'certificate verify failed: self signed certificate' in str(e):
            #works with 'https://self-signed.badssl.com/' 'https://untrusted-root.badssl.com/'
            info += ssl_date(hostname, 443, info)
            info += " Error: self signed certificate or the root is untrusted\n"
            return info

        if 'getaddrinfo failed' in str(e):
            #https://unexistent-domain-example.com
            info += " Error: site does not exist or was misspelled \n"
            return info 

        if('doesn\'t match either of' or 'certificate verify failed: unable to get local issuer certificate' in str(e)):
            #https://www.school57.kiev.ua/
            #http://mihvpu.zp.ua/
            #http://vpu40.ptu.org.ua
            message = "Certificate name mismatch. Possible reason: website does not use SSL and has no certificate.\
                        This may be caused by a misconfiguration, no certificate installed or an attacker intercepting your connection.\n"
            print(message)
            info += message
            return info

        if 'No connection could be made because the target machine actively refused it' in str(e):
            info += 'No connection could be made because the target machine actively refused it. Check if your server is up and running.'
            print(info)
            sys.exit()
        
        info+="Connection error"
        print(str(e))
        return info

    except req.exceptions.RequestException as e:
        if 'NewConnectionError' in str(e):

            #print(f"Cannot connect: {str(e)}")
            info+= "No connection could be made because the target machine actively refused it\n \
                    There are no open ports that are listening to the connections\n"
            return info
        else: 
            info+= "Request exception occured.\n"
            return info   
            
    except Exception as e:    
        message = "Error occured" + str(e)
        print(message)
        info += message
        #info+=ssl_date(hostname, 443, info)
        return info

    print("...", url, "connection successful")
    info+=ssl_date(hostname, 443, info)
    info+="Valid trusted certificate found!\n"
    return info


if __name__ == "__main__":
    
    url = "https://hackxpert.com/ratsite/register.php" 

    info = ssl_enter(url)
    print(info)

