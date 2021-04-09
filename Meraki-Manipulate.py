# Copyright (c) 2021 Cisco and/or its affiliates.
#
# This software is licensed to you under the terms of the Cisco Sample
# Code License, Version 1.1 (the "License"). You may obtain a copy of the
# License at
#
#                https://developer.cisco.com/docs/licenses
#
# All use of the material herein must be in accordance with the terms of
# the License. All rights not expressly granted by the License are
# reserved. Unless required by applicable law or agreed to separately in
# writing, software distributed under the License is distributed on an "AS
# IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied.

# Title
# Maraki Add Users
#
# Language
# Python 3.5
#
# Description
# This script will take a list of users in a pescribed format and add them to the WiFi databsed baised on the details
# given by the user of the script Most of the script can be used to mass produce any/all features that are not
# included in the documented provisionaing API. PLEASE only use this for things NOT in the API.
#
# NOTE Since creating the below the feature is now in the API. Published only incase something is not in API in future.
#
# Contacts
# Phil Bridges - phbridge@cisco.com
#
# EULA
# This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges with a
# variety of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and arrangements.
# Until provision of alcohol or baked goodies your on your own but there is no rocket science involved so don't panic too
# much. To accept this EULA you must include the correct flag when running the script. If this script goes crazy wrong and
# breaks everything then your also on your own and Phil will not accept any liability of any type or kind. As this script
# belongs to Phil and NOT Cisco then Cisco cannot be held responsible for its use or if it goes bad, nor can Cisco make
# any profit from this script. Phil can profit from this script but will not assume any liability. Other than the boring
# stuff please enjoy and plagiarise as you like (as I have no ways to stop you) but common curacy says to credit me in some
# way [see above comments on Beer, Wine, Steak and Greggs.].
#
# Version Control               Comments
# Version 0.01 Date 29/02/16     Inital draft
# Version 0.02 Date 01/03/16     Removed all pre-token compliocation and just look username/password combos Login now appears to work
# Version 0.03 Date 02/03/16     Built all the POST messages and formatting but get some annoying bad auth message even when sending the same string given by previous GET
# Version 0.04 Date 03/03/16     Login now works fine dealt the the URL encoding that was causing bad auth on user add POST
# Version 0.05 Date 08/03/16     Included some proper ouput logging to the logfile
# Version 0.06 Date 12/03/16	 Added more debugging output to logfile
# Version 0.07 Date 12/03/16     Added connection check before proceding
# Version 0.08 Date 11/04/16     Added EULA to cover my ass.
# Version 0.09 Date 12/04/16     Added password randomisation
# Version 0.10 Date 14/04/16     Added handeling of modified by NAME/E-MAIL - Also created second way to parse auth token just for fun
#
# Version 6.9 Date xx/xx/xx     Took over world and actuially got paid for value added work....If your reading this approach me on linkedin for details of weekend "daily" rate
# Version 7.0 Date xx/xx/xx     Note to the Gaffer - if your reading this then the above line is a joke only :-)
#
# ToDo *******************TO DO*********************
# DONE 1.0 Check if password when sent needs to be URL encoded or not simular to how the username is sent.
# 2.0 Removed. No comments under further investigation
# PART 3.0 Make the errorhandleing better thoughout
# DONE 4.0 print some output for debugging
# DONE 5.0 add IP/connection check before proceding
# DONE 6.0 Randomise password better
#
#

import argparse                     # needed for the nice menus and variable checking
from datetime import datetime       # needed for the datetime for filename
import csv                          # needed for parsing csv files in lazy way
import requests                     # for all the http/https stuff
import random                       # needed for password randomisation
import string                       # also needed for passwor randomisation
from bs4 import BeautifulSoup       # parsing for authtoken
import urllib                       # convert string to url encoded string
import re                           # The use of re could maybe be done nicer with bs4 but I dont know how at this stage
import StringIO                     # Used for the parsing of some raw values

parser = argparse.ArgumentParser(description='process input')
parser.add_argument("-nonotify", "--notification_email", required=False, default=True, action='store_false',
                    help="email should be sent to new users - Default is to send to users", )
parser.add_argument("-r", "--registered", required=False, default=True,
                    help='unknown variable always seams to be True so far')
parser.add_argument("-u", "--username", required=True, default="test@test.com",
                    help="username to use to login to the portal")
parser.add_argument("-s", "--secret_password", required=True, default="password",
                    help="password used to loginto the portal (must have admin rights)")
parser.add_argument("-f", "--seedfile", type=argparse.FileType('rb', ), required=True,
                    help='file path of seed file with user details 1 per line')
parser.add_argument("-w", "--wifiname", required=False, default="Test-WiFi",
                    help="name of the WiFi network to add users to CaSe SenSiTivE", )
parser.add_argument("-v", "--verbose", action='store_true', default=False, help="increase output verbosity", )
parser.add_argument("-p", "--proxy", required=False, default=False,
                    help="define a proxy for both http and https if required", )
parser.add_argument("-ACCEPTEULA", "--acceptedeula", action='store_true', default=False,
                    help="Marking this flag accepts EULA embedded withing the script")
args = parser.parse_args()

if args.acceptedeula == False:
    print("""you need to accept the EULA agreement which is as follows:-
# EULA
# This software is provided as is and with zero support level. Support can be purchased by providing Phil bridges with a
# variety of Beer, Wine, Steak and Greggs pasties. Please contact phbridge@cisco.com for support costs and arrangements.
# Until provision of alcohol or baked goodies your on your own but there is no rocket science involved so don't panic too
# much. To accept this EULA you must include the correct flag when running the script. If this script goes crazy wrong and
# breaks everything then your also on your own and Phil will not accept any liability of any type or kind. As this script
# belongs to Phil and NOT Cisco then Cisco cannot be held responsible for its use or if it goes bad, nor can Cisco make
# any profit from this script. Phil can profit from this script but will not assume any liability. Other than the boring
# stuff please enjoy and plagiarise as you like (as I have no ways to stop you) but common curacy says to credit me in some
# way [see above comments on Beer, Wine, Steak and Greggs.].

# To accept the EULA please run with the -ACCEPTEULA flag
    """)
    quit()

if args.verbose:
    print("-v Verbose flag set printing extended ouput")
    print("seed file loaded is ", str(args.seedfile.name))
print("Arguments and files loaded")
if args.verbose:
    print(str(args.notification_email))
    print(str(args.registered))
    # print (str(args.authenticity_token))
    # print (str(args.auth_name))
    # print (str(args.auth_email))

num_of_users = sum(1 for line in open(args.seedfile.name)) - 1
working_user_index = 1  # would be 0 if no description line in seed file

if args.verbose:
    print("total number of users ", num_of_users)
    print("revvered up lets get going")

try:
    if args.verbose:
        print("trying to create file")
    output_filename = datetime.now()
    if args.verbose:
        print(str(output_filename))
    output_log = open(str(output_filename), 'a+')
    if args.verbose:
        print("file created sucessfully")
except:
    print("something went bad opening/creating file for writing")
    quit()

if not args.proxy:
    if args.verbose:
        print("no proxy settings detected")
else:
    use_proxies = {
        'http': 'http://' + args.proxy,
        'https': 'http://' + args.proxy,
    }
    if args.verbose:
        print("proxy flag detected setting proxies")
        print(use_proxies)

output_log.write("checking for internet connection")
try:
    if not args.proxy:
        connection_check = requests.get("http://www.bbc.co.uk", timeout=5)
    else:
        connection_check = requests.get("http://www.bbc.co.uk", timeout=5, proxies=use_proxies, verify=False)
    # HTTP errors are not raised by default, this statement does that
    connection_check.raise_for_status()
    output_log.write("Internet connection found proceding")
except requests.HTTPError as e:
    print("Checking internet connection failed, status code {0}.".format(e.response.status_code))
    output_log.write("Checking internet connection failed, status code {0}.".format(e.response.status_code))
    quit()
except requests.ConnectionError:
    print("No internet connection available.")
    output_log.write("No internet connection available.")
    quit()

print(datetime.now())
# with requests.session() as meraki_session:
meraki_session = requests.session()
output_log.write("Getting login screen datetime is " + str(datetime.now()))
try:
    if not args.proxy:
        get_login_screen = meraki_session.get("https://account.meraki.com/login/dashboard_login?go=")
    else:
        get_login_screen = meraki_session.get("https://account.meraki.com/login/dashboard_login?go=",
                                              proxies=use_proxies, verify=False)
except:
    print(
        "something bad happened and couldnt fetch login page - There appears to be some connectivity maybe check for captive portal?")
output_log.write("Login screen got datetime is " + str(datetime.now()))
output_log.write("response from login was " + str(get_login_screen.status_code))
if args.verbose:
    try:
        print("verbose flag set creating get_login_screen.text")
        output_get_login_screen = open("get_login_screen.text", 'w')
        print("file created sucessfully")
        output_get_login_screen.write(get_login_screen.text)
        print("written get_login_screen.text to get_login_screen.text")
    except:
        print("something went bad opening/creating file for writing")
        quit()

if get_login_screen.status_code == 200:
    print("Response from Login splash looking good moving forwards Response was 200 OK")
else:
    print("something might not be quite right")
    print(get_login_screen.status_code)

print(datetime.now())
soup_parsed_login_response = BeautifulSoup(get_login_screen.text)
login_authenticity_token = soup_parsed_login_response.input['value']

# This is maybe not needed as the login stage takes a non URL encoded authenticity_token or a URL encoded one
login_authenticity_token_url_encoded = soup_parsed_login_response.select('input[name="authenticity_token"]')
if args.verbose:
    print(login_authenticity_token_url_encoded)
login_authenticity_token_url_encoded = \
str(login_authenticity_token_url_encoded[0]).split("value=", 3)[1].split("/>", 1)[0]
if args.verbose:
    print("after split")
    print(login_authenticity_token_url_encoded)
    print("remove quotes")
login_authenticity_token_url_encoded = login_authenticity_token_url_encoded[1:-1]
if args.verbose:
    print("before encodeing")
login_authenticity_token_parse_url_encoded = urllib.quote_plus(login_authenticity_token_url_encoded)
if args.verbose:
    print("post encoding")
    print(login_authenticity_token_parse_url_encoded)
if args.verbose:
    print("printing token non encoded")
    print(login_authenticity_token)
    print("printed token non encoded")

login_post_url = "https://account.meraki.com/login/login"
host_ID = login_post_url.split('//', 1)[-1]  # Split right and left to get the defined host from marki cluster
login_post_payload = "authenticity_token=" + login_authenticity_token_url_encoded + "&email=" + urllib.quote_plus(
    args.username) + "&password=" + urllib.quote_plus(args.secret_password) + "&commit=Log+in&goto=manage&go="
# Questionable if the headers is needed but it does make the request look more like the browser request.
login_post_headers = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.6.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-GB,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "https://account.meraki.com/login/dashboard_login?go=",
    "Connection": "close",
    "Content-Type": "application/x-www-form-urlencoded",
}
#    "Content-Length": "152",
# "Host": "account.meraki.com",

if args.verbose:
    print("printing post headers")
    print(login_post_headers)
    print("printing post payload")
    print(login_post_payload)
output_log.write("seding details to login dateime was " + str(datetime.now()))
if args.proxy == False:
    login_post_send = meraki_session.post(login_post_url, headers=login_post_headers, data=login_post_payload)
else:
    login_post_send = meraki_session.post(login_post_url, headers=login_post_headers, data=login_post_payload,
                                          verify=False, proxies=use_proxies)
output_log.write("Logged into page dateime was " + str(datetime.now()))
output_log.write("sent post to login prompt POST response was " + str(login_post_send.status_code))
if args.verbose:
    try:
        print("verbose flag set creating login_post_send.text")
        output_login_post_send = open("login_post_send.text", 'w')
        print("file created sucessfully")
        output_login_post_send.write(login_post_send.text)
        print("written login_post_send.text to login_post_send.text")
        print("verbose flag set creating login_post_send.text")
        output_content_login_post_send = open("content_login_post_send.text", 'w')
        print("file created sucessfully")
        output_content_login_post_send.write(login_post_send.content)
        print("written login_post_send.text to content_login_post_send.text")
    except:
        print("something went bad opening/creating file for writing")
        quit()

# this below is nasty implement better method
try:
    if str(login_post_send.history[0]) == "<Response [302]>":
        print("Response from Login looking good moving forwards Response was 302 Found")
    elif login_post_send.status_code == 200:
        print("Response from Login was bad auth redirected to login page again - 200 OK")
        quit()
    else:
        print("something might not be quite right")
        print(login_post_send.status_code)
        print(login_post_send.history)
except:
    if login_post_send.status_code == 200:
        print("Response from Login was bad auth redirected to login page again - 200 OK")
        quit()
    else:
        print("something might not be quite right")
        print(login_post_send.status_code)
        print(login_post_send.history)
# above is not nice make something nicer
# woof
print(datetime.now())
user_file = open(args.seedfile.name, "rb")
user_file_reader = csv.reader(user_file, delimiter=",")

soup_parsed_login_response = BeautifulSoup(login_post_send.text)
redirect_meraki_host = soup_parsed_login_response.form['action']
meraki_host = redirect_meraki_host.rsplit(".", 2)[0].split("//", 1)[1]

login_post_send_parse = StringIO.StringIO(login_post_send.content)
for line in login_post_send_parse:
    if re.search("Mkiconf.current_user", line):
        if args.verbose:
            print(line)
            print(line.rsplit('"', 10)[3])
            print(line.rsplit('"', 10)[7])
        mki_current_user = line.rsplit('"', 10)[3]
        mki_current_email = line.rsplit('"', 10)[7]
    if re.search("Mkiconf.authenticity_token", line):   # Note this is not currently used as we grab this via BS4
        if args.verbose:                                # Note this is not currently used as we grab this via BS4
            print(line)                                 # Note this is not currently used as we grab this via BS4
            print(line.rsplit('"', 5)[1])               # Note this is not currently used as we grab this via BS4
        mki_auth_token = line.rsplit('"', 5)[1]         # Note this is not currently used as we grab this via BS4

if args.verbose:
    print("auth token for making change")
authenticity_token_parse = soup_parsed_login_response.select('input[name="authenticity_token"]')
if args.verbose:
    print(authenticity_token_parse)
authenticity_token_parse_half = str(authenticity_token_parse[0])
if args.verbose:
    print(authenticity_token_parse_half)
authenticity_token_parse_nearlycomplete = authenticity_token_parse_half.split("value=", 3)[1].split("/>", 1)[0]
authenticity_token_parse_complete = authenticity_token_parse_nearlycomplete[1:-1]
if args.verbose:
    print(authenticity_token_parse_complete)
authenticity_token_parse_complete_url_encoded = urllib.quote_plus(authenticity_token_parse_complete)
if args.verbose:
    print(authenticity_token_parse_complete_url_encoded)
if args.verbose:
    print(redirect_meraki_host)
    print(meraki_host)

add_user_url = "https://" + meraki_host + ".meraki.com/" + args.wifiname + "/n/Viv1wcad/manage/configure/update_guests?send_emails=" + str(
    args.notification_email)
add_user_post_headers = {
    "Host": meraki_host + ".meraki.com",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.6.0",
    "Accept": "*/*",
    "Accept-Language": "en-GB,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Referer": "https://" + meraki_host + ".meraki.com/Test-WiFi/n/Viv1wcad/manage/configure/guests",
    "Connection": "close",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "X-Requested-With": "XMLHttpRequest",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
}

print(datetime.now())
output_log.write("Started all interations of POST dateimte is " + str(datetime.now()))
row = {}
for row in user_file_reader:
    time_used = str((datetime.now() - datetime(1970, 1, 1)).total_seconds())
    password_to_submit = ''.join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(8))
    if args.verbose:
        print("Row #" + str(user_file_reader.line_num) + " " + str(row))
        print("Description " + row[0])
        print("Email Address " + row[1])
        print("Authorized " + row[2])
        print(time_used)
        print(row)
        print(password_to_submit)

    if args.verbose:
        print("working on line" + str(user_file_reader.line_num) + "submitting user" + row[
            0])  # this line is annoying in non debugging output maybe remove or make better
    output_log.write("working on line" + str(user_file_reader.line_num) + "submitting user" + row[0])
    output_log.write(str(datetime.now()))

    add_user_post_payload = "authenticity_token=" + authenticity_token_parse_complete_url_encoded + "&is_client_vpn=false&expire_time=%7B%7D&expire_units=60&ssid%5Bnumber%5D=0&edited%5B0%5D%5Bname%5D=" + \
                            row[0] + "&edited%5B0%5D%5Bemail%5D=" + row[1].replace("@",
                                                                                   "%40") + "&edited%5B0%5D%5Baccount_type%5D=Meraki+802.1X&edited%5B0%5D%5Bauthorized%5D=true&edited%5B0%5D%5Bpassword%5D=" + password_to_submit + "&edited%5B0%5D%5Bsend_password%5D=" + str(
        args.notification_email).lower() + "&edited%5B0%5D%5Bexpires_at%5D=0&edited%5B0%5D%5Bauth_is_admin%5D=false&edited%5B0%5D%5Bauth_name%5D=" + urllib.quote_plus(
        mki_current_user) + "&edited%5B0%5D%5Bauth_email%5D=" + urllib.quote_plus(
        mki_current_email) + "&edited%5B0%5D%5Bcreated_at%5D= " + time_used + "&edited%5B0%5D%5Bmeraki_radius%5D=true&edited%5B0%5D%5B%24%24%5D=0"
    # args.auth_name.replace(" ", "+")
    # args.auth_email.replace("@", "%40")
    if args.verbose:
        print(add_user_post_payload)

    if not args.proxy:
        add_user_post_send = meraki_session.post(add_user_url, headers=add_user_post_headers,
                                                 data=add_user_post_payload)
    else:
        add_user_post_send = meraki_session.post(add_user_url, headers=add_user_post_headers,
                                                 data=add_user_post_payload, verify=False, proxies=use_proxies)
    if add_user_post_send.status_code != 200:
        print("something might have gone bad response from post was " + str(add_user_post_send.status_code))
    if args.verbose:
        print(add_user_post_send.text)
        print(add_user_post_send.status_code)

        # insert some writing to file to keep track of the job and to follow errors on bigger jobs.

    if args.verbose:
        print("finish on line" + str(user_file_reader.line_num) + "submitting user" + row[
            0])  # this line is annoying in non debugging output maybe remove or make better
    print(
        "POST for line " + str(user_file_reader.line_num) + " submitting user" + row[0] + "completed with code " + str(
            add_user_post_send.status_code))
    output_log.write("finish on line" + str(user_file_reader.line_num) + "submitting user" + row[0] + "\n")
    output_log.write(
        "Completed iteration and submission POST response code is " + str(add_user_post_send.status_code) + "\n")
    output_log.write(str(datetime.now()))
print(datetime.now())
output_log.write("Everthing all done time is now " + str(datetime.now()))
print("job completed Phil needs a payrise")
print("all done going to the pub")
output_log.close()