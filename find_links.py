import requests as req
from urllib.parse import urlparse
from bs4 import BeautifulSoup as bs
import sys
import requests
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

result_links = []
counter = 1
#store found actions
#if action in list
#skip at once
used_actions = []

def check_link(ini_link):
    links_from_page = set()
    soup = bs(req.get(ini_link).text, "html.parser")
    try:
        refs = soup.find_all("a")
        #take first 100
        if len(refs) > 100:
            refs = refs[0:100]
    except Exception as e:
        print(str(e))
        sys.exit()

    domn = urlparse(ini_link).netloc

    
    for a in refs:
        global used_actions
        dest_link =''
        relative_ref = a.get("href")

        #don't construct same refs
        if relative_ref in used_actions:
            continue
        used_actions.append(relative_ref)

        if relative_ref == "#" or relative_ref == "/" or not relative_ref or relative_ref == "":
            #no sense to test
            continue
        
        try:
            dest_psd = urlparse(relative_ref)
            if(all([dest_psd.scheme, dest_psd.netloc, requests.get(relative_ref, timeout=5, verify = False) ])):
                #link starts with schema(absolute)
                psd_ini = urlparse(ini_link)
                if psd_ini.netloc == dest_psd.netloc:
                    dest_link = relative_ref
                    print(f"<< Valid sublink: \t{dest_link} >>")
                    links_from_page.add(dest_link)
                    result_links.append(dest_link)
        except:
            psd_ini = urlparse(ini_link)
            dom_ini, schema_ini, action_ini = psd_ini.netloc, psd_ini.scheme, psd_ini.path
            if relative_ref[0] != '/':
                relative_ref = '/'+relative_ref
            dest_link = schema_ini +"://"+ dom_ini + '' + relative_ref
            psd_dest = urlparse(dest_link)
            try:
                reply = requests.get(dest_link, timeout=5, verify = False)
                if(all([psd_dest.scheme, psd_dest.netloc, reply]) and  reply.status_code!=404):
                    pass
                else:
                    continue
            except:
                continue
            if dest_link in result_links :
                continue
            if domn not in dest_link:
                continue

            print(f" << Valid sublink: \t{dest_link} >>")
            links_from_page.add(dest_link)
            result_links.append(dest_link)
        
    return links_from_page
     


def recursive_search(url, depth, stop_links_num=20):
    global counter
    counter +=1
    
    depth +=1
    links = check_link(url)
    print("...Extracting links from " + url)
    try:
        for link in links:
            
            if counter > stop_links_num:
                break
            if depth > 10:
                #too deep
                break
            recursive_search(link, depth, stop_links_num)
    except Exception as e:
        print(e)
        sys.exit()


def base_search(url, stop_links_num = 20):
    #head
    depth = 0
    result_links.append(url)
    recursive_search(url, depth, stop_links_num)

    if len(result_links) > 1:
        print("... Were found "+ str(len(result_links))+ " links")
    else:
        print("... None sublinks found.")
    return result_links

def enter_search_links(link, numlinks=None):
    stop_links_num = 20 
    if numlinks != None:        
        internal_url = base_search(link, numlinks)
    else: 
        internal_url= base_search(link, stop_links_num)
    internal_urls = list(internal_url)
    return internal_urls

if __name__ == '__main__':

    ini_link = 'http://testphp.vulnweb.com/categories.php'
    links = enter_search_links(ini_link,3)
    for each in links:
        print(each)
    print(len(links))