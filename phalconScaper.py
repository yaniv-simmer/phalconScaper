import requests
from pathlib import Path
import os
from datetime import datetime


class AttackIncident:
    """
    A class to represent an attack incident, encapsulating details about the project affected,
    the financial loss incurred, the type of vulnerability exploited, and the transactions involved.

    Attributes:
        project (str): The name of the project attacked.
        loss (float): The financial loss incurred due to the attack, in USD.
        vulnerability (str): The type of vulnerability exploited in the attack.
        transactions (list): A list of dictionaries, each representing a transaction involved in the attack.
    """

    def __init__(self, project: str, loss: float, vulnerability: str, transactions: list, rootCause: str = None):
        self.project = project
        self.loss = loss
        self.vulnerability = vulnerability
        transactions_data = []
        for txn in transactions:
            new_tx = {}
            new_tx['tx_hash'] = txn['txnHash']
            date, time = convert_txn_date(txn['txnHashDate'])
            new_tx['tx_date'] = date
            new_tx['tx_time'] = time
            new_tx['tx_chain'] = txn['chainId']

            transactions_data.append(new_tx)
        self.transactions = transactions_data
        self.rootCause = rootCause


def convert_txn_date(txn_hash_date: int) -> tuple[str, str]:
    """
    Converts a timestamp from milliseconds to a formatted date and time string.

    Parameters:
        txn_hash_date (int): The timestamp in milliseconds to be converted.

    Returns:
        tuple[str, str]: A tuple containing the formatted date string in 'YYYY-MM-DD' format
                         and the time string in 'HH:MM' format.
    """
    # Convert from milliseconds to seconds
    date_in_seconds = txn_hash_date / 1000
    # Convert to datetime object
    date_obj = datetime.utcfromtimestamp(date_in_seconds)
    # Format date and time
    date, time = date_obj.strftime('%Y-%m-%d , %H:%M').split(',')
    return date, time


def process_data(data: dict) -> list[AttackIncident]:
    """
    Processes the raw data into a list of AttackIncident objects.

    Parameters:
        data (dict): The raw data to process, expected to contain a list of attack incidents.

    Returns:
        list[AttackIncident]: A list of AttackIncident objects, each representing an attack incident.
    """
    attack_incidents_list = []
    for attack in data['list']:
        incident = AttackIncident(project=attack['project'],
                                  loss=attack['loss'],
                                  vulnerability=attack['rootCause'],
                                  transactions=attack['transactions'],
                                  rootCause=attack['media']
                                  )
        attack_incidents_list.append(incident)
    return attack_incidents_list


def make_request(url: str, json_data: dict) -> dict:
    """
    Makes a POST request to the specified URL with the given JSON data and returns the JSON response.

    Parameters:
        url (str): The URL to make the request to.
        json_data (dict): The JSON data to send in the request.

    Returns:
        dict: The JSON response data, or None if the response is empty.
    """
    response = requests.post(url=url, json=json_data)
    if response.text:
        return response.json()
    else:
        print("Empty response received")
        return None


def write_to_csv(attack_incidents_list: list[AttackIncident]) -> None:
    """
    Writes a list of AttackIncident objects to a CSV file, creating a structured report.

    Parameters:
        attack_incidents_list (list[AttackIncident]): The list of AttackIncident objects to write.
    """
    with open('out/attack_incidents.csv', 'w') as file:
        file.write('Project, Loss, Vulnerability, root cause link, Transactions, Date, Time, Chain\n')
        for attack_incident in attack_incidents_list:
            file.write(f'{attack_incident.project},'
                   f'{attack_incident.loss},'
                   f'{attack_incident.vulnerability},'
                   f'{attack_incident.rootCause}')

            # Write each transaction under the Transaction column
            for i, tx in enumerate(attack_incident.transactions):
                if i != 0:
                    file.write(' , , ,')
                file.write(f',{tx["tx_hash"]},{tx["tx_date"]},{tx["tx_time"]},{tx["tx_chain"]}\n')


def main():
    """
    Main function to orchestrate the data fetching, processing, and writing to CSV.
    Orchestrates the flow of data from fetching, processing to writing it into a CSV file.
    """
    dirpath = Path("./out")

    if not dirpath.is_dir():
        os.mkdir(dirpath)

    url = "https://phalcon.blocksec.com/api/v1/attack/events"
    json_data = {
        "page": 1,
        "pageSize": 200,
        "endTime": 1735682399000,
        "date": "desc"}

    data = make_request(url, json_data)
    attack_incidents_list = process_data(data)
    write_to_csv(attack_incidents_list)


if __name__ == "__main__":
    main()
