import time
from typing import List

import redis
from rq import Connection, Queue
from rq.job import Job

from core.prospector import prospector
from core.report import generate_report
from llm.llm_service import LLMService
from util.config_parser import LLMServiceConfig, parse_config_file

# get the redis server url
config = parse_config_file()
# redis_url = config.redis_url
backend = config.backend

redis_url = "redis://localhost:6379/0"


def run_prospector(vuln_id, v_int, enabled_rules, report_type: str):
    """Call the prospector() and generate_report() functions. This also creates the LLMService singleton
    so that it is available in the context of the job.
    """

    print(enabled_rules)
    config = LLMServiceConfig(
        type="sap",
        model_name="gpt-4",
        temperature=0.0,
        ai_core_sk="sk.json",
        use_llm_repository_url=True,
    )
    LLMService(config)

    results, advisory_record = prospector(
        vulnerability_id=vuln_id,
        version_interval=v_int,
        backend_address=backend,
        enabled_rules=[rule.id for rule in enabled_rules],
        use_llm_repository_url=True,
    )
    generate_report(
        results,
        advisory_record,
        report_type,
        f"data_sources/reports/{vuln_id}",
    )

    return results, advisory_record


def dispatch_jobs_to_queue(cves: List[str], enabled_rules) -> bool:
    """Dispatches a job for each CVE in the list of CVEs from config.yaml. Only returns when the jobs are finished."""

    # Send them to Prospector to run & save results to data_source/reports/<cve_id>
    for cve in cves:
        with Connection(redis.from_url(redis_url)):
            queue = Queue()

            job = Job.create(
                run_prospector,
                args=(cve, "None:None", enabled_rules, "json"),
                description="Prospector Job",
                id=cve,
            )

            queue.enqueue_job(job)

    print(f"Dispatched {len(cves)} jobs.")

    jobs = Job.fetch_many(cves, connection=redis.from_url(redis_url))
    while any(
        [
            job.get_status(refresh=True) in ["queued", "scheduled", "started"]
            for job in jobs
        ]
    ):
        time.sleep(2)

    for cve in cves:
        job = Job.fetch(cve, connection=redis.from_url(redis_url))
        print(f"{cve} job finished with status {job.get_status(refresh=True)}.")

    # Down here, the jobs have finished.
    print("Jobs finished.")
    return True
