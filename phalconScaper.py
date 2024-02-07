import requests
from pathlib import Path
import os
from datetime import datetime

class AttackIncident:
    """
    A class to represent an attack incident.
    """
    def __init__(self, project: str, loss: float, vulnerability: str, transactions: list):
        self.project = project
        self.loss = loss
        self.vulnerability = vulnerability
        transactions_data = []
        for txn in transactions:
            new_tx = {}
            new_tx['tx_hash'] = txn['txnHash']
            date , time = convert_txn_date(txn['txnHashDate'])
            new_tx['tx_date'] = date
            new_tx['tx_time'] = time    
            new_tx['tx_chain'] = txn['chainId']

            transactions_data.append(new_tx)
        self.transactions = transactions_data


def convert_txn_date(txn_hash_date):
    """
    Converts a timestamp from milliseconds to a formatted date string.

    Parameters:
        txn_hash_date (int): The timestamp in milliseconds to be converted.

    Returns:
        str: The formatted date string in 'DD:MM:YYYY , HH:MM' format.
    """
    # Convert from milliseconds to seconds
    date_in_seconds = txn_hash_date / 1000
    # Convert to datetime object
    date_obj = datetime.utcfromtimestamp(date_in_seconds)
    # Format date and time
    date , time = date_obj.strftime('%d:%m:%Y , %H:%M').split(',')
    return date , time



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
                                  vulnerability=attack['rootCause'],
                                  transactions=attack['transactions'])
        #print(attack['transactions'],'\n\n')
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
        file.write('Project, Loss, Vulnerability, Transactions, Date, Time, Chain\n')
        for attack_incidents in attack_incidents_list:  
            file.write(f'{attack_incidents.project},\
                {attack_incidents.loss},\
                {attack_incidents.vulnerability}')
            for i, tx in enumerate(attack_incidents.transactions):
                # Write each transaction under the Transaction column
                if (i != 0):
                    file.write(' , ,')
                tx_hash = tx['tx_hash']
                tx_date = tx['tx_date']
                tx_time = tx['tx_time']
                tx_chain = tx['tx_chain']
                file.write(f',{tx_hash},{tx_date},{tx_time},{tx_chain}\n')
                print(f'{tx_date},{tx_time},{tx_chain}\n')
            

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

url = "https://phalcon.blocksec.com/api/v1/attack/events"
json_data = {
    "page": 1,
    "pageSize": 200,
    "endTime": 1735682399000,
    "date": "desc"
}
data = make_request(url, json_data)