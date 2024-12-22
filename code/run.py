# Do not edit this script!

import json
import sys
import importlib

def read_json():
    try:
        config_file = "config.json"
        with open(config_file, 'r') as f:
            config = json.load(f)
    except:
        print("Error: Unable to load config.json")

    try:
        covert_channel_name = config["covert_channel_code"]
    except:
        print("Error: Unable to load 'covert_channel_name' from config.json")
    try:
        send_params = config["send"]["parameters"]
    except:
        print("Error: Unable to load send parameters from config.json")
    try:
        receive_params = config["receive"]["parameters"]
    except:
        print("Error: Unable to load receive parameters from config.json")

    try:
        covert_channel_file_and_class_name = "MyCovertChannel"
        module = importlib.import_module(covert_channel_file_and_class_name)
        covert_channel_class = getattr(module, covert_channel_file_and_class_name)
        covert_channel = covert_channel_class()
    except (ImportError, AttributeError) as e:
        print(f"Error: Unable to load class {covert_channel_file_and_class_name} from module {covert_channel_file_and_class_name}.")

    return (covert_channel, send_params, receive_params)

covert_channel, send_params, receive_params = read_json()
if sys.argv[1] == "send":
    covert_channel.send(**send_params)
elif sys.argv[1] == "receive":
    covert_channel.receive(**receive_params)
