import os
import requests

def all_paths(path):

    path_list = []
    for root, _, files in os.walk(path):
        for filename in files:
            path_list.append(os.path.join(root, "\\", filename))
    return path_list

def submit_to_virustotal(api_key, path):

    with open(path, "rb") as f:

        files = {'file': f}
        url = "https://www.virustotal.com/api/v3/files"
        headers = {"x-apikey": api_key}
        response = requests.post(url, files=files , headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data['data']['id']
        else:
            print(f"Error submitting file: {response.text}") #aaa
            return None
        
def get_hash_from_analyses(id):
    
    url = f'https://www.virustotal.com/api/v3/analyses/{id}'
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()['meta']['file_info']['sha256']
    else:
        print(f"Error getting analysis status: {response.text}")
        return None

def get_file_report(api_key, hash):

    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()['data']['attributes']['last_analysis_stats']
    else:
        print(f"Error getting scan results: {response.text}")
        return None

api_key = '6c98224bedab17e010a3a89f9bcbf0a28292b4671c81a92151195d9037f6a2be'
path = r'D:\\!objectcheck\\app.py'

id = submit_to_virustotal(api_key, path)
hash = get_hash_from_analyses(id)

print(get_file_report(api_key, hash))