# Analysis of Commit Classification Rule

This folder contains the scripts to analyse the commit classification rule.

## Questions to answer

1. How many times do the results differ when running Prospector without the CC rule compared to with the CC rule?
2. Does adding the CC rule improve Prospector's results?

## Experiment

### Variable Parameters in the Experiment

1. Number of top candidate commits to apply the rule to (eg. 3, 5, 10)
2. Definition of successful Prospector report can mean different things, eg.:
    1. Fixing commit is the first commit
    2. Fixing commit among first X commits

### Experiment Methodology

1. Have a list of ground truth CVEs from Project-KB to compare to later.
2. Run "vanilla" Prospector on those CVEs and check how many are correct to obtain a baseline.
3. Run Prospector with the CC rule on these and
   1. check how often the order of commits has changed (Question 1)
   2. check how many of the results are correct and compare to vanilla (Question 2)

## File Structure

* **config.yaml**: A configuration file to set parameters, such as filenames, directories, Prospector settings, ...
* **fetch.py**: Fetches the CVEs specified in config.yaml and saves them locally to a JSON file (the name of which is also set in config.yaml)
* **analyse.py**: Dispatches the CVEs specified in config.yaml as jobs to Prospector and "analyses" them. Analyses means that it compiles the relevant data from the Prospector reports (after the jobs have finished) into one JSON file, easier to analyse further (the name of this is set in config.yaml)
* **compare.py**: This file contains functions to find answers to the questions. It compares the results of Prospector runs with different settings (eg. in this case with or without the commit classification rule).
