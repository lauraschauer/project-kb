import json
import os

from omegaconf import OmegaConf

from evaluation.scripts.jobs import dispatch_jobs_to_queue
from rules.rules import RULES_PHASE_1, RULES_PHASE_2

config = OmegaConf.load("evaluation/experiments/config.yaml")
# Set rules
enabled_rules = []
if "RULES_PHASE_1" in config.rules:
    enabled_rules += RULES_PHASE_1
if "RULES_PHASE_2" in config.rules:
    enabled_rules += RULES_PHASE_2

cves_to_dispatch = list(
    set(config.cves)
    - set([fn.replace(".json", "") for fn in os.listdir("data_sources/reports/")])
)
print(len(cves_to_dispatch))
# Dispatch jobs to prospector
dispatch_jobs_to_queue(cves=cves_to_dispatch, enabled_rules=enabled_rules)

# Analyse the created reports
results = {"vulnerabilities": {}}  # The JSON template to save results to

cves_to_analyse = set(config.cves) & set(
    [fn.replace(".json", "") for fn in os.listdir("data_sources/reports/")]
)  # get the set of reports where a CVE is set in config.yaml and the corresponding report got successfully generated
print(f"Found {len(cves_to_analyse)} CVEs to analyse: {cves_to_analyse}")

for cve in cves_to_analyse:
    filepath = config.prospector_reports + cve + ".json"
    with open(filepath, "r") as f:
        data = json.load(f)

    if not data:
        print(f"Error: JSON file for {cve} could not be found.")

    individual_result = {
        "commits": [],
    }

    for commit in data["commits"][:10]:
        commit_relevance = sum([rule["relevance"] for rule in commit["matched_rules"]])
        matched_llm_rule = "COMMIT_IS_SECURITY_RELEVANT" in [
            rule["id"] for rule in commit["matched_rules"]
        ]
        individual_result["commits"].append(
            {
                "commit_hash": commit["commit_id"],
                "relevance": sum(
                    [rule["relevance"] for rule in commit["matched_rules"]]
                ),
                "matched_llm_rule": "yes" if matched_llm_rule else "no",
            }
        )

    results["vulnerabilities"][cve] = individual_result

file = config.analysis_results
with open(file, "w") as f:
    json.dump(results, f)
