#!/usr/bin/env python3

import http.client
import json
import urllib.parse
import ssl
import hashlib
import getpass
import time

DEBUG = False

# Official Facebook for Android keys
CLIENT_ID = '256002347743983'
CLIENT_SECRET = '374e60f8b9bb6b8cbb30f78030438895'

def debug(msg):
    if DEBUG:
        print(f"DEBUG: {msg}")

def get_oauth_token(email, cid, did, mid, uid, password):
    try:
        auth_data = {
            "api_key": CLIENT_ID,
            "api_secret": CLIENT_SECRET,
            "email": email,
            "password": password,
            "credentials_type": "password",
            "generate_session_cookies": "1",
            "device_id": did,
            "machine_id": mid,
            "uuid": uid,
            "cid": cid,
            "format": "json",
            "generate_machine_id": "1",
            "locale": "en_US",
            "client_country_code": "US",
            "method": "auth.login",
            "fb_api_req_friendly_name": "authenticate",
            "fb_api_caller_class": "com.facebook.account.login.protocol.Fb4aAuthHandler",
            "access_token": f"{CLIENT_ID}|{CLIENT_SECRET}",
            "meta_inf_fbmeta": "",
            "advertiser_id": did,
            "currently_logged_in_userid": "0",
            "family_device_id": did,
            "device_id": did,
            "app_id": CLIENT_ID,
            "android_sdk_version": "30",
            "network_type": "WIFI"
        }

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-G960F Build/QQ3A.200805.001) [FBAN/FB4A;FBAV/396.1.0.28.104;]",
            "X-FB-Connection-Type": "WIFI",
            "X-FB-HTTP-Engine": "Liger",
            "X-FB-Client-IP": "true",
            "X-FB-Server-Cluster": "true",
            "X-FB-Device-ID": did,
            "X-FB-SIM-HNI": "26001",
            "Authorization": "OAuth " + f"{CLIENT_ID}|{CLIENT_SECRET}"
        }

        conn = http.client.HTTPSConnection('b-api.facebook.com', context=ssl._create_unverified_context())
        params = urllib.parse.urlencode(auth_data)
        
        debug(f"Sending request with parameters: {params}")
        
        conn.request('POST', '/method/auth.login', params, headers)
        response = conn.getresponse()
        response_data = response.read().decode()
        
        debug(f"Status: {response.status}")
        debug(f"Response: {response_data}")
        
        response_json = json.loads(response_data)

        if 'access_token' in response_json:
            return response_json['access_token']
        elif 'error_data' in response_json:
            try:
                error_data = json.loads(response_json['error_data'])
                if 'login_first_factor' in error_data:
                    debug("2FA Required")
                    two_factor_code = getpass.getpass('2FA Code: ')
                    
                    auth_data.update({
                        'credentials_type': 'two_factor',
                        'twofactor_code': two_factor_code,
                        'userid': error_data.get('uid'),
                        'machine_id': error_data.get('machine_id'),
                        'first_factor': error_data.get('login_first_factor')
                    })

                    params = urllib.parse.urlencode(auth_data)
                    conn.request('POST', '/method/auth.login', params, headers)
                    response = conn.getresponse()
                    response_data = response.read().decode()
                    response_json = json.loads(response_data)
            except json.JSONDecodeError:
                debug("Cannot decode error_data")
            
            if 'access_token' in response_json:
                return response_json['access_token']
        
        return None

    except Exception as e:
        debug(f"An error occurred: {e}")
        return None
    finally:
        conn.close()

def main():
    global DEBUG
    
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option('-d', '--debug', action='store_true', dest='debug', default=False)
    (options, args) = parser.parse_args()
    DEBUG = options.debug

    print("Please enter your Facebook authentication details:")
    email = input("Email: ")
    cid = input("CID: ")
    did = input("DID: ")
    mid = input("MID: ")
    uid = input("UID: ")
    password = getpass.getpass("Password: ")
    
    token = get_oauth_token(email, cid, did, mid, uid, password)
    
    if token:
        print("\nOAuth token obtained successfully:")
        print(token)
        print("\nYou can use this token in bitlbee with:")
        print(f"account add facebook {token}")
    else:
        print("\nFailed to obtain OAuth token")

if __name__ == "__main__":
    main()
