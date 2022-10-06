from pymongo import MongoClient
from creds import db_string
import certifi
import sys

ca = certifi.where()

try:

    db_client = MongoClient(db_string, tlsCAFile=ca)
    db = db_client.test
    # print("Connection successful")

except Exception as e:
    print(str(e))
    print("<< Probably bad Internet or IP is not allowed to connect >>")
    sys.exit()

try:
    current_db = db_client["vuln"]
    scan_collection = current_db["scan"]
    lut_collection = current_db["lut"]

except Exception as e:
    print(str(e))
    sys.exit()


