#!/usr/bin/python3
import logging
import os
import signal
import sys
from typing import Any, Dict

from dotenv import load_dotenv

import llm.operations as llm
from llm.model_instantiation import create_model_instance
from util.http import ping_backend

path_root = os.getcwd()
if path_root not in sys.path:
    sys.path.append(path_root)


import core.report as report  # noqa: E402
from cli.console import ConsoleWriter, MessageStatus  # noqa: E402
from core.prospector import TIME_LIMIT_AFTER  # noqa: E402
from core.prospector import TIME_LIMIT_BEFORE  # noqa: E402
from core.prospector import prospector  # noqa: E402; noqa: E402

# Load logger before doing anything else
from log.logger import get_level, logger, pretty_log  # noqa: E402
from stats.execution import execution_statistics  # noqa: E402
from util.config_parser import get_configuration  # noqa: E402

# from util.http import ping_backend  # noqa: E402


def main(argv):  # noqa: C901
    with ConsoleWriter("Initialization") as console:
        config = get_configuration(argv)
        if not config:
            logger.error(
                "No configuration file found, or error in configuration file. Cannot proceed."
            )

            console.print(
                "No configuration file found, or error in configuration file. Check logs.",
                status=MessageStatus.ERROR,
            )
            return

        logger.setLevel(config.log_level)
        logger.info(f"Global log level set to {get_level(string=True)}")

        if config.vuln_id is None:
            logger.error("No vulnerability id was specified. Cannot proceed.")
            console.print(
                "No configuration file found.",
                status=MessageStatus.ERROR,
            )
            return

        # instantiate LLM model if set in config.yaml
        if config.llm_service:
            model = create_model_instance(llm_config=config.llm_service)

        if not config.repository and not config.use_llm_repository_url:
            logger.error(
                "Either provide the repository URL or allow LLM usage to obtain it."
            )
            console.print(
                "Either provide the repository URL or allow LLM usage to obtain it.",
                status=MessageStatus.ERROR,
            )
            sys.exit(1)

        # if config.ping:
        #     return ping_backend(backend, get_level() < logging.INFO)

        config.pub_date = (
            config.pub_date + "T00:00:00Z" if config.pub_date is not None else ""
        )

        logger.debug("Using the following configuration:")
        pretty_log(logger, config.__dict__)

        logger.debug("Vulnerability ID: " + config.vuln_id)

    if not config.repository:
        config.repository = llm.get_repository_url(model=model, vuln_id=config.vuln_id)

    results, advisory_record = prospector(
        vulnerability_id=config.vuln_id,
        repository_url=config.repository,
        publication_date=config.pub_date,
        vuln_descr=config.description,
        version_interval=config.version_interval,
        modified_files=config.modified_files,
        advisory_keywords=config.keywords,
        use_nvd=config.use_nvd,
        # fetch_references=config.fetch_references,
        backend_address=config.backend,
        use_backend=config.use_backend,
        git_cache=config.git_cache,
        limit_candidates=config.max_candidates,
        # ignore_adv_refs=config.ignore_refs,
    )

    if config.preprocess_only:
        return

    report.generate_report(
        results, advisory_record, config.report, config.report_filename
    )

    execution_time = execution_statistics["core"]["execution time"][0]
    ConsoleWriter.print(f"Execution time: {execution_time:.3f}s\n")

    return


def signal_handler(signal, frame):
    logger.info("Exited with keyboard interrupt")
    sys.exit(0)


if __name__ == "__main__":  # pragma: no cover
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv)
