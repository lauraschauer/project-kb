import json
import os

directory = "data_sources/reports/"

results = {"vulnerabilities": []}

# Now analyse the reports
for filename in os.listdir(directory):
    filepath = directory + filename
    with open(filepath, "r") as f:
        data = json.load(f)

    if not data:
        print("Error occured, JSON file could not be found.")

    cve_id = data["advisory_record"]["cve_id"]
    repository_url = (
        data["commits"][0]["repository"] if len(data["commits"]) > 0 else ""
    )

    single_result = {
        "repository_url": repository_url or "",
        cve_id: {
            "relevance": [],
            "no_llm_rule_match": [],
        },
    }

    for commit in data["commits"][:10]:
        commit_relevance = sum([rule["relevance"] for rule in commit["matched_rules"]])
        matched_llm_rule = "COMMIT_IS_SECURITY_RELEVANT" in [
            rule["id"] for rule in commit["matched_rules"]
        ]
        single_result[cve_id]["relevance"].append(
            {
                "commit_hash": commit["commit_id"],
                "relevance": sum(
                    [rule["relevance"] for rule in commit["matched_rules"]]
                ),
                "matched_llm_rule": "yes" if matched_llm_rule else "no",
            }
        )
        # if commit["matched_rules"]:
        #     print(commit["matched_rules"][0]["relevance"]) # Sanity check

        # if "COMMIT_IS_SECURITY_RELEVANT" not in [
        #     rule["id"] for rule in commit["matched_rules"]
        # ]:
        #     single_result[cve_id]["no_llm_rule_match"].append(commit["commit_id"])

    results["vulnerabilities"].append(single_result)


# print(json.dumps(results))  # sanity check
file = "evaluation/results/no_llm_results.json"
with open(file, "w") as f:
    json.dump(results, f)
