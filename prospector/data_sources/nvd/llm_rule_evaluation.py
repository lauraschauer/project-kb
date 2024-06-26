from datetime import datetime

from data_sources.nvd.filter_entries import (
    find_matching_entries_test,
    get_cves,
    get_from_nvd,
)
from data_sources.nvd.job_creation import create_prospector_job
from util.report_analyzer import analyze_commit_relevance_results

# Request CVE Entries from the last 10 days
# cves = get_cves(10, date=datetime(2023, 1, 10))

cves = get_from_nvd("CVE-2020-1925")
print(cves["vulnerabilities"][0]["cve"]["id"])

# Filter out undesired CVEs based on keywords in project_metadata.json
# filtered_cves = find_matching_entries_test(cves)
# print("These are the metached CVEs:")
# for cve in filtered_cves:
#     print(cve["vulnerabilities"][0]["cve"]["id"])

reported_cves = []
# Send them to Prospector to run
if cves:
    res = create_prospector_job(
        repository_url="https://github.com/apache/olingo-odata4",
        cve_id=cves["vulnerabilities"][0]["cve"]["id"],
        report_type="json",
    )  # Creates .json files for each CVE in app/data_sources/reports
    if res["job_data"]["job_status"]:
        reported_cves.append(cves["vulnerabilities"][0]["cve"]["id"])
