from util.report_analyzer import analyze_commit_relevance_results

for cve in ["CVE-2024-22263", "CVE-2024-35527"]:
    # Analyse the reports
    analyze_commit_relevance_results(f"data_sources/reports/{cve}.json")
