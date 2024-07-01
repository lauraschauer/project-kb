import json

from omegaconf import OmegaConf

config = OmegaConf.load("evaluation/experiments/commit_classification/config.yaml")

# Load the JSON data from the files
with open(config.file1, "r") as f1, open(config.file2, "r") as f2:
    commit_classification = json.load(f1)
    no_commit_classification = json.load(f2)


# Function to extract the commit order for each CVE
def extract_commit_order(data):
    commit_order = {}
    for vuln in data["vulnerabilities"]:
        for cve, details in vuln.items():
            if cve != "repository_url" and "relevance" in details:
                commit_order[cve] = [
                    item["commit_hash"] for item in details["relevance"]
                ]
    return commit_order


# Extract commit orders from both files
commit_order_classification = extract_commit_order(commit_classification)
commit_order_no_classification = extract_commit_order(no_commit_classification)

# Compare the orders and count changes
order_changes = 0

for cve in commit_order_classification:
    if cve in commit_order_no_classification:
        if commit_order_classification[cve] != commit_order_no_classification[cve]:
            order_changes += 1
            print(f"Order changed for {cve}")
            # print(f"commit_classification: {commit_order_classification[cve]}")
            # print(f"no_commit_classification: {commit_order_no_classification[cve]}")

print(
    f"Total number of order changes: {order_changes} out of {len(commit_order_classification)}"
)
