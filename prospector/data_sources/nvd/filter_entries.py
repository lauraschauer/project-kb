import csv
import datetime
import json
from typing import List

import requests
from versions_extraction import extract_version_ranges_cpe, process_ranges

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?"


def get_cves(days, date=datetime.datetime.now(), keywords: List[str] = []):
    """Gets CVEs published in the last `days` days counting from `date`. Default for `date` is today.

    Params:
        days (int): The number of days before today to look for CVEs for.
        date (): The date to start counting from.
    """

    data = ""

    # calculate the date to retrieve new entries (%Y-%m-%dT%H:%M:%S.%f%2B01:00)
    date_now = date
    start_date = (date_now - datetime.timedelta(days=days)).strftime(
        "%Y-%m-%dT%H:%M:%S"
    )
    end_date = date_now.strftime("%Y-%m-%dT%H:%M:%S")

    params = {
        "pubStartDate": start_date,
        "pubEndDate": end_date,
        "keywordSearch": "".join(keywords),
    }

    # Retrieve the data from NVD
    try:
        response = requests.get(NVD_BASE_URL, params=params)
    except Exception as e:
        print(str(e))

    if response.status_code == 200:
        data = json.loads(response.text)

    else:
        print("Error while trying to retrieve entries")

    return data


def get_from_nvd(cve_id: str):
    """Get an advisory from the NVD dtabase"""
    try:
        params = {"cveId": cve_id}

        response = requests.get(NVD_BASE_URL, params=params)

        if response.status_code == 200:
            return json.loads(response.text)

        else:
            print("Error occured.")

    except Exception as e:
        print(f"Error occured: {e}")


def get_cve_by_id(id):
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveID={id}"

    try:
        print(nvd_url)
        response = requests.get(nvd_url)
    except Exception as e:
        print(str(e))

    if response.status_code == 200:
        data = json.loads(response.text)
        # print(data["vulnerabilities"])

    else:
        print("Error while trying to retrieve entries")

    return data


def write_list_to_file(lst, filename):
    with open(filename, "w") as file:
        for item in lst:
            file.write(str(item) + "\n")


def csv_to_json(csv_file_path):
    with open(csv_file_path, "r") as csv_file:
        csv_reader = csv.reader(csv_file)
        data = []
        # Skip the header row
        next(csv_reader)
        # Loop through the rows of the file
        for row in csv_reader:
            # Create a dictionary for the row data
            row_data = {"project": row[0], "service_name": row[1], "repository": row[2]}
            data.append(row_data)
    # Convert to JSON object
    json_data = json.dumps(data)
    return json_data


def find_matching_entries_test(data):
    """Filters a list of CVEs by checking if their descriptions contain certain keywords and adds their version interval.
    Returns a list of CVEs that contain at least one keyword. The returned list also contains the version interval information.
    """
    with open("./data/project_metadata.json", "r") as f:
        match_list = json.load(f)

    filtered_cves = []

    # for vuln in data["vulnerabilities"]:
    for d in match_list.values():
        keywords = data["search keywords"]
        for keyword in keywords:
            if keyword in data["cve"]["descriptions"][0]["value"]:
                lst_version_ranges = extract_version_ranges_cpe(data["cve"])
                version = process_ranges(lst_version_ranges)
                filtered_cves.append(
                    {
                        "nvd_info": data,
                        "repo_url": d["git"],
                        "version_interval": version,
                    }
                )
                break

    return filtered_cves
