import json

def load_config(config_path):
    with open(config_path, 'r') as file:
        return json.load(file)

def save_config(config, config_path):
    with open(config_path, 'w') as file:
        json.dump(config, file, indent=4)
