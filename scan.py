import click
from ssl_check import ssl_enter
from xss import xss_enter
from sql import sql_enter
from check_headers import *
from helper import verify_link
from datetime import datetime
from report_db import save_report, get_report_by_link, get_all_links
from find_links import enter_search_links
import sys


#main_group
@click.group()
def cli():
    pass

#groups
@cli.group()
def reports():
    print("Reports section entered\n")
    pass

@reports.command()
def listreports():
    '''
    This will list all the sites for which scanning was made
    '''
    get_all_links()


@reports.command()
@click.argument('link')
def readreport(link):
    ''' 
    Check if link is in the db and provide report if it is
    '''
    get_report_by_link(link)


#commands

########################################

@cli.command()
@click.argument('link')
@click.option('--opt', '-o', multiple = True, type = click.Choice(['ssl', 'xss', 'sql', 'headers']), help = 'Choose what to scan for')
@click.option('--save', is_flag=True, show_default=True, default=False, help = 'specify it to save report to database after scan')

def sitescan(link, opt, save):
    '''
    This will scan one site without traversal with specified options (-o <option>)\n
    Options: ssl, xss, sql, headers\n
    Example: sitescan http://www.google.com -o headers -o sql
    '''
    #validation of the url
    verify_link(link)
    
    info = {"ssl": "null",
            "xss": "null",
            "sql": "null",
            "headers": "null"}
    

    if opt == ():
        print('No options specified')
        print('Provide options via -o <option> parameter')
        sys.exit()

    print(f"SCANNING THE LINK \t {link}")

    if 'ssl' in opt:
        ssl_info = ssl_enter(link)
        info['ssl'] = ssl_info


    if 'xss' in opt:
        xss_info = xss_enter(link)
        info['xss'] = xss_info 

    if 'sql' in opt:
        sql_info = sql_enter(link)
        info['sql'] = sql_info

    if 'headers' in opt:
        headers_info = enter_headers(link)
        # print(headers_info)
        info['headers'] = headers_info

    if save == True:

        today_date = datetime.today()

        save_report(link, today_date, info, type = 'sitescan')
        print("\n\n")

        get_report_by_link(link)
        
    else:
        print("\n\n<< No-save report>>")
        print(f"<< Results for {link}>>")
        #insert no-save report
        for each in info:
            if info[each] != 'null':
                print(f"... {each} information")
                print(info[each])
    #save report in (?) string format maybe like site, date, report
    #not save

    # print(type(options))

@cli.command()
@click.argument('link')
@click.option('--opt', '-o', multiple = True, type = click.Choice(['ssl', 'xss', 'sql', 'headers']), help = 'Choose what to scan for')
@click.option('--numlinks', '-n', type = int, help = 'How many links to go through in search for relative urls.\n \
     If not specified, the default number is 20')
@click.option('--save', is_flag=True, show_default=True, default=False, help = 'specify it to save report to database after scan')
def subscan(link, opt, numlinks, save):
    '''
    This will try to find sublinks with specified options (-o <option>)\n
    Options: ssl, xss, sql, headers\n
    Example: subscan google.com -o xss -o sql
    '''

    verify_link(link)
    print(opt)

    if numlinks is not None and numlinks < 1:
        print("<< Positive number more than 1 must be provided with -n option >>")
        sys.exit()

    if numlinks is not None and numlinks > 100:
        print("<< Provide -n option up to 100 >>")
        sys.exit()

    print("... Scan this link pass it lower")   
    internal_urls = enter_search_links(link, numlinks)
    
    if len(internal_urls) == 0:
        print("<< No refs were found for the link.>>")
        sys.exit()

    outer_info = { 
            "link": link,
            "ssl": "null",
            "sublink_list": "ssl-only"
            }

    sublink_list = []
    
    if opt == ():
        print('No options specified')
        print('Provide options via -o <option> parameter')
        sys.exit()

    today_date = datetime.today()

    if 'ssl' in opt:
        ssl_info = ssl_enter(link)
        
        outer_info['ssl'] = ssl_info
        
        
    if('sql' not in opt and 'xss' not in opt and 'headers' not in opt):
        if save == True:
            save_report(link, today_date, outer_info, type = 'subscan')
            print("\n\n")
            get_report_by_link(link)
            
        else:
            print("\n\n<< No-save report>>")
            print(f"<< Results for {link}>>")
            print(ssl_info)     
        return

    i = 0
    for each_url in internal_urls:
        i+=1
        print("\nNumber of scanning: "+str(i)+ "\t"+each_url)   
        sublink_info = {
        "sublink": each_url,
        "xss": "null",
        "sql": "null",
        "headers": "null"
    }
        if 'xss' in opt:
            xss_info = xss_enter(each_url)
            sublink_info['xss'] = xss_info 

        if 'sql' in opt:
            sql_info = sql_enter(each_url)
            sublink_info['sql'] = sql_info

        if 'headers' in opt:
            headers_info = enter_headers(each_url)
            #print(headers_info)
            sublink_info['headers'] = headers_info

        sublink_list.append(sublink_info)

    outer_info['sublink_list'] = sublink_list
    
    if save == True:
        save_report(link, today_date, outer_info, type = 'subscan')
        print("\n\n")
        get_report_by_link(link)
    else:
        print("\n\n<< No-save report>>")
        print(f"<< Results for {link}>>")
        if outer_info['ssl'] != 'null':
            print(outer_info['ssl'])

        for each in outer_info['sublink_list']:
            for sublink in each:
                if each[sublink] != 'null':
                    print(each[sublink])
                    


if __name__ == "__main__":
    try:
        cli()
        input()
    except Exception as e:
        print(str(e))
        sys.exit()