import json
import os
import sys
import time
from datetime import datetime

import requests
import yaml
from dotenv import load_dotenv

from data_sources.nvd.filter_entries import (
    find_matching_entries_test,
    get_cve_by_id,
    get_cves,
)

load_dotenv()


def save_single_cve(output_file: str, cve_id: str):
    with open(output_file, "a+") as f:
        data = get_cve_by_id(cve_id)
        filtered_cves = find_matching_entries_test(data)
        json.dump(filtered_cves, f)
        print("Saved a single CVE.")


def save_multiple_cves(output_file: str):
    with open(output_file, "w") as f:
        data = get_cves(10)
        filtered_cves = find_matching_entries_test(data)
        json.dump(filtered_cves, f)
        print("Saved multiple CVEs.")


def fetch_apache_2023(output_file: str):
    with open(output_file, "w+") as f:
        try:
            data = get_cves(
                120, date=datetime(2023, 12, 31, 23, 59, 59), keywords=["Apache"]
            )
        except Exception as e:
            print(f"Fetching the data caused the following error: {e}")
            sys.exit(1)
        filtered_cves = find_matching_entries_test(data)
        json.dump(filtered_cves, f)
        print("Saved 2023 Apache CVEs (for now just the 120 last days of 2023).")


def fetch_data(mode: str, output_file: str):
    """Calls the data fetching method corresponding to the 'mode' given.

    Params:
        mode: Describes which data to fetch: single = a single CVE,
              multipe = CVEs from the last 10 days, apache23 = Apache CVEs from 2023.
        output_file: Where to save the CVE data to.
    """
    if mode == "single":
        save_single_cve(output_file, "CVE-2020-1925")
    elif mode == "multiple":
        save_multiple_cves(output_file)
    elif mode == "apache23":
        fetch_apache_2023(output_file)
    else:
        print(f"{mode} not in list of availble datasets.")


def fetch_ground_truth(year: str, output_file: str):
    """Fetches data from project KB, which has the ground truth for vulnerability patches.

    Params:
        output_file (str): Where to save the project KB data to.
    """
    print("Fetching data from Project KB (on GitHub)...")
    # GitHub Repository details
    api_url = "https://api.github.com/repos/SAP/project-kb/contents/statements?ref=vulnerability-data"
    auth = {"Authorization": f"Bearer {os.getenv('GITHUB_ACCESS_TOKEN')}"}

    # Get the contents of a file from GitHub
    def get_github_file_content(file_url):
        response = requests.get(file_url, headers=auth)
        if response.status_code == 200:
            file_data = response.json()
            # time.sleep(0.5)
            # print("Made request") # Sanity check
            return yaml.safe_load(requests.get(file_data["download_url"]).text)
        else:
            print(f"Failed to fetch file from {file_url}: {response.reason}")
            return None

    # Initialise data structure
    data = {"ground_truth": []}

    # Fetch the list of directories in the statements folder
    response = requests.get(api_url)
    # print(response.text)
    if response.status_code == 200:
        contents = response.json()
        for item in contents:
            if item["type"] == "dir" and item["name"].startswith("CVE-" + year):
                # Fetch the statement.yaml file of the directory
                statement_file_url = f"https://api.github.com/repos/SAP/project-kb/contents/statements/{item['name']}/statement.yaml?ref=vulnerability-data"
                statement_data = get_github_file_content(statement_file_url)
                # Only write the ones that contain fixes
                if statement_data and not (statement_data.get("fixes") is None):
                    data["ground_truth"].append(statement_data)
    else:
        print("Failed to fetch directory contents.")

    # Write the output to a file
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)


def load_data(file: str):
    """Helper to load data from a json file.
    Params:
        file: The filepath to the JSON file where the data is stored.
    """
    with open(file, "r") as f:
        return json.load(f)
