import os
import requests

def all_paths(path):

    path_list = []
    for root, _, files in os.walk(path):
        for filename in files:
            path_list.append(os.path.normpath(os.path.join(root, filename)))
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
            print(f"Error submitting file: {response.text}")
            return None
        
def get_hash_from_analyses(api_key, id):
    
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
    


def all_paths_scan(path):
    
    api_key = '6c98224bedab17e010a3a89f9bcbf0a28292b4671c81a92151195d9037f6a2be'
    paths_list = all_paths(path)
    results_list = []

    for item in paths_list:
        id = submit_to_virustotal(api_key, item)
        hash = get_hash_from_analyses(api_key, id)
        scan_results = get_file_report(api_key, hash)
        malicious_count = scan_results['malicious']
        suspicious_count = scan_results['suspicious']
        undetected_count = scan_results['undetected']
        harmless_count = scan_results['harmless']
        timeout_count = scan_results['timeout']
        confirmed_timeout_count = scan_results['confirmed-timeout']
        failure_count = scan_results['failure']
        type_unsupported_count = scan_results['type-unsupported']

        result = f'{item} - safe file'
        if malicious_count > 0:
            if undetected_count > malicious_count:
                result = f'{item} - could be malicious, further investigation needed'
            else:
                result = '{item} - malicious file, please take action'
        
        if undetected_count == 0 and suspicious_count > 0:
            result = '{item} - could be malicious, further investigation needed'

        if timeout_count+confirmed_timeout_count+failure_count >= harmless_count+suspicious_count+malicious_count+undetected_count:
            result = '{item} - file not reliably scanned, further investigation needed'
        
        results_list.append(result)
    return results_list
        


# api_key = '6c98224bedab17e010a3a89f9bcbf0a28292b4671c81a92151195d9037f6a2be'

# paths_list = all_paths(path)

# id = submit_to_virustotal(api_key, paths_list[1])
# hash = get_hash_from_analyses(id)

# print(get_file_report(api_key, hash))

# path = r'D:\\!objectcheck'
# print(all_paths_scan(path))
