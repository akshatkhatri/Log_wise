import re
import pprint
import pandas as pd

def log_data_to_df(file_path):
    
    valid_requests_dict_list = []

    regex_pattern = r'(?P<IP>\d+\.\d+\.\d+\.\d+) - - \[(?P<Date>\d{2}/\w+/\d{4}):(?P<Time>\d{2}:\d{2}:\d{2}) \+(?P<Time_zone>\d{4})\] "(?P<Request_method>\w+) (?P<Path>[^ ]+) (?P<Protocol>[^"]+)" (?P<Response_code>\d{3}) (?P<Response_size>\d+) "(?P<Referrer>[^"]*)" "(?P<User_Agent>[^"]*)"'

    with open(file_path,'r') as f, open('malformed_requests.log','a') as mf:
        print('Running.....')
        for line in f:
            match_obj = re.search(regex_pattern,line)
            if match_obj:
                valid_requests_dict_list.append(match_obj.groupdict())
            else:
                mf.write(line)

    df = pd.DataFrame(valid_requests_dict_list)
    return df

def log_list_to_df(list_path):
    valid_requests_dict_list = []

    regex_pattern = r'(?P<IP>\d+\.\d+\.\d+\.\d+) - - \[(?P<Date>\d{2}/\w+/\d{4}):(?P<Time>\d{2}:\d{2}:\d{2}) \+(?P<Time_zone>\d{4})\] "(?P<Request_method>\w+) (?P<Path>[^ ]+) (?P<Protocol>[^"]+)" (?P<Response_code>\d{3}) (?P<Response_size>\d+) "(?P<Referrer>[^"]*)" "(?P<User_Agent>[^"]*)"'

    for line in list_path:
        match_obj = re.search(regex_pattern,line)
        if match_obj:
            valid_requests_dict_list.append(match_obj.groupdict())

    df = pd.DataFrame(valid_requests_dict_list)
    return df