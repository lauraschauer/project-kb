# Evaluation

This folder contains any files related to evaluating Prospector. There are two types of files:

1. **Script Files**: To run Prospector on a batch of CVEs, or to obtain and save a batch of CVEs.
2. **Data Files**: These contain either fetched CVE data or Prospector results.

## Script Files

### data_interaction.py

This file contains the functions to fetch CVE data, and save the data to files or load CVE data from files. To fetch CVE data, it uses the functions given in filter_entries.py, which make the API calls to the NVD API.

1. `save_single_cve()`: Saves the CVE record of CVE-202-1925 to evaluation/cve_data/single_cve.json
2. `load_single_cve()`: Loads and returns the JSON record of evaluation/cve_data/single_cve.json
3. `save_multiple_cves()`: Saves all relevant CVE records from the last ten days to evaluation/cve_data/multiple_cves.json
4. `load_multiple_cves()`: Loads and returns the JSON records of evaluation/cve_data/multiple_cves.json

### job_creation.py

This file contains functions to create and enqueue a Prospector job.

1. `create_prospector_job()`: Creates a new queue, creates a job and returns the job's response object containing the job ID, status, description, creation dates, and result. This function takes the following arguments:
   1. The CVE ID
   2. The repository URL of the repository affected by the CVE
   3. The version interval for the relevant commit range
   4. The report type
2. `run_prospector()`: Gets called by the above function, and call itself `prospector()` and then `generate_report()` on the results of `prospector()`. Anything created in this function, will be available when `prospector()` is run, for example, the `LLMService` singleton.

### dispatch_jobs.py

This file ties the functionality of the previous two together. It optionally fetches CVE data using `data_interaction.py`. If the CVE data is already saved, it will load the saved data, otherwise, it will fetch new data.
For each CVE in the loaded data, it creates a prospector job with report type "json" using `job_creation.py`. `job_creation.py` calls `prospector()`, which creates JSON reports in the backend docker container in `app/evaluation/llm_results.json`. This can be copied to the host machine using:

```bash
docker cp <prospector_backend_1-ID>:/app/evaluation/llm_results.json evaluation/results
```

### analyse.py

This file takes the Prospector JSON reports as input and produces output files with the analysis of them. The output files containing the results are saved in `evaluation/results/`.

## Data Files

The folder `cve_data` contains the files with CVE data fetched from the NVD API.

The folder `results` contains the analysis results created by analysis scripts.
