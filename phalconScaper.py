import requests
from pathlib import Path
import os

class AttackIncident:
    """
    A class to represent an attack incident.
    """
    def __init__(self, project, loss, chain, vulnerability, date, transactions):
        self.project = project
        self.loss = loss
        self.chain = chain
        self.vulnerability = vulnerability
        self.date = date
        self.transactions = transactions

def process_data(data: dict) -> list[AttackIncident]:
    """
    Processes the raw data into a list of AttackIncident objects.

    Parameters:
        data (dict): The raw data to process.

    Returns:
        list[AttackIncident]: A list of AttackIncident objects.
    """
    attack_incidents_list = []
    for attack in data['list']:
        incident = AttackIncident(project=attack['project'],
                                  loss=attack['loss'],
                                  chain=attack['chainIds'],
                                  vulnerability=attack['rootCause'],
                                  date=attack['date'],
                                  transactions=attack['transactions'])
        attack_incidents_list.append(incident)
    return attack_incidents_list

def make_request(url: str, json_data: dict) -> dict:
    """
    Makes a POST request to the specified URL with the given JSON data.

    Parameters:
        url (str): The URL to make the request to.
        json_data (dict): The JSON data to send in the request.

    Returns:
        dict: The JSON response data.
    """
    response = requests.post(url=url, json=json_data)
    if response.text:
        return response.json()
    else:
        print("Empty response received")
        return None

def write_to_csv(attack_incidents_list: list[AttackIncident]) -> None:
    """
    Writes a list of AttackIncident objects to a CSV file.

    Parameters:
        attack_incidents_list (list[AttackIncident]): The list of AttackIncident objects to write.
    """
    with open('out/attack_incidents.csv', 'w') as file:
        file.write('Project, Loss, Chain, Vulnerability, Date, Transactions\n')
        for incident in attack_incidents_list:
            file.write(f"{incident.project},\
                {incident.loss},\
                {incident.chain},\
                {incident.vulnerability},\
                {incident.date},\
                {incident.transactions}\n")

def main():
    """
    Main function to orchestrate the data fetching, processing, and writing to CSV.
    """
    dirpath = Path("./out")
    print("Main function started")

    if not dirpath.is_dir():
        os.mkdir(dirpath)
    url = "https://phalcon.blocksec.com/api/v1/attack/events"
    json_data = {
        "page": 1,
        "pageSize": 200,
        "endTime": 1735682399000,
        "date": "desc"
    }
    data = make_request(url, json_data)
    attack_incidents_list = process_data(data)
    write_to_csv(attack_incidents_list)
    
if __name__ == "__main__":
    main()

