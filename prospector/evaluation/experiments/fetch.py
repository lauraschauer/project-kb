import json
import os

from evaluation.scripts.fetch_data import fetch_ground_truth
from evaluation.scripts.jobs import dispatch_jobs_to_queue
from omegaconf import OmegaConf

from rules.rules import RULES_PHASE_1, RULES_PHASE_2

config = OmegaConf.load("evaluation/experiments/commit_classification/config.yaml")
raw_data_dir = "evaluation/data/raw"


# ## First, get the data and save them to the file in config.raw_data_file,
# ## If the file already exists, do not overwrite it (if you want to overwrite, uncomment the next 8 lines)
# if (
#     config.raw_data_file in os.listdir("evaluation/data/raw/")
#     and config.delete_existing_raw
# ):
#     os.remove(
#         os.path.join(raw_data_dir, config.raw_data_file)
#     )  # delete the file if needed
# Fetch data if there is no file existing yet
if config.raw_data_file not in os.listdir("evaluation/data/raw/"):
    fetch_ground_truth(
        year=config.year, output_file=os.path.join(raw_data_dir, config.raw_data_file)
    )

# Get the ground truth from the JSON file and load it into 'data'
with open(os.path.join(raw_data_dir, config.raw_data_file), "r") as f:
    data = json.load(f)

# Check length of the obtained file
print(
    f"Found {len(data['ground_truth'])} CVEs with their fixing commit (ground truth)."
)  # sanity check for ground truth data (won't work for other data fetched)

# ## Running Prospector on this data should be done in analyse.py
