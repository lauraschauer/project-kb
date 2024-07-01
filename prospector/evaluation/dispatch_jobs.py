import json
from datetime import datetime

from data_sources.nvd.job_creation import create_prospector_job
from evaluation.data_interaction import (
    load_multiple_cves,
    load_single_cve,
    save_multiple_cves,
    save_single_cve,
)
from llm.llm_service import LLMService
from util.config_parser import LLMServiceConfig
from util.report_analyzer import analyze_commit_relevance_results

# # Save CVE Data
# save_single_cve()
# # Load CVE Data
# cves = load_single_cve()

# save_multiple_cves()
cves = load_multiple_cves()
print(f"Loaded {len(cves)} CVEs.")

for cve in cves:
    print(cve["nvd_info"]["cve"]["id"])
    # print(cve)

# Create the LLM Service outside, since this only calls prospector()
config = LLMServiceConfig(
    type="sap",
    model_name="gpt-4",
    temperature=0.0,
    ai_core_sk="sk.json",
    use_llm_repository_url=True,
)
LLMService(config=config)

# Send them to Prospector to run & save results to data_source/reports/<cve_id>
for cve in cves:
    res = create_prospector_job(
        repository_url=cve["repo_url"],
        cve_id=cve["nvd_info"]["cve"]["id"],
        report_type="json",
        version_interval=cve["version_interval"],
    )  # Creates .json files for each CVE in app/data_sources/reports
    # if res["job_data"]["job_status"]:
    #     reported_cves.append(cves["vulnerabilities"][0]["cve"]["id"])
