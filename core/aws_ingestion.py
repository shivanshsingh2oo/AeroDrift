import json


def load_mock_aws_data():
    with open("data/mock_aws.json", "r") as file:
        data = json.load(file)

    return data