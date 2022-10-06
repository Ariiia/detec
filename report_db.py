from db_connection import scan_collection as collection
import sys

def save_report(link, today_date, info, type):

    #https://stackoverflow.com/questions/30553406/python-bson-errors-invaliddocument-cannot-encode-object-datetime-date2015-3
    
    #only one latest link at a time
    check_if_is = collection.find_one({"link" : link})
    if check_if_is:
        collection.delete_one({"link" : link})
    if type == 'sitescan':
        inserti = {"link": link, "date": today_date, "type": type, "ssl": info['ssl'], "sql": info['sql'],
         "xss": info['xss'], "headers": info['headers'] }
    elif type == 'subscan':
        inserti = {"link": link, "date": today_date, "type": type, "ssl": info['ssl'], "sublinks": info['sublink_list'] }

    ins_result = collection.insert_one(inserti)

def get_report_by_link(link):

    report = collection.find_one({"link" : link})
    if report != None:
        print('REPORT INFO: ')
        print("LINK SCANNED: ")
        print(report['link'])
        print("DATE OF THE LAST SCAN: ")
        print(report['date'])
        if(report['ssl'] != "null"):
            print("\n SSL INFORMATION")
            print(report['ssl'])

        if report['type'] == "sitescan":
            if(report['xss'] != "null"):
                print("\n XSS INFORMATION")
                print(report['xss'])
                
            if(report['sql'] != "null"):
                print("\n SQL INFORMATION")
                print(report['sql'])

            if(report['headers'] != "null"):
                print("\n HEADERS INFORMATION")
                print(report['headers'])
        #if report type is with sublinks but only ssl
        elif report['type'] == "subscan":
        #ACCOUNT THAT SSL MAY BE THE ONLY ASKED OPTION
            if report['sublinks'] == "ssl-only":
                print('NOTICE FOR REPORT :')
                print('No other options than ssl were provided for a subscan')
                return
            else:
                i=0
                for each in report['sublinks']:
                    i+=1
                    print("SUBLINK SCANNED NUMBER "+str(i)+' ')
                    print(each['sublink'])

                    # print(each['xss'])
                    if(each['xss'] != "null"):
                        print("\n XSS INFORMATION")
                        print(each['xss'])
                    
                    if(each['sql'] != "null"):
                        print("\n SQL INFORMATION")
                        print(each['sql'])

                    if(each['headers'] != "null"):
                        print("\n HEADERS INFORMATION")
                        print(each['headers'])

    else:
        print(f"No report was found for the link {link}. Check spelling and try again.")


def get_all_links():
    
    try:
        records = list(collection.find({}))
    except Exception as e:
          print(e)
          sys.exit()

    if not records:
        print("No reports have been saved yet.")
    else: 
        print("All the links which were scanned: \n")
        for each in records:
            print(each['link'])
        print('\n')

        print('You can now copy any of it to check the report with reports readreport <link> parameter\n')
