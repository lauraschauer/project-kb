from langchain.prompts import FewShotPromptTemplate, PromptTemplate

examples_data = [
    {
        "cve_description": "Apache Olingo versions 4.0.0 to 4.7.0 provide the AsyncRequestWrapperImpl class which reads a URL from the Location header, and then sends a GET or DELETE request to this URL. It may allow to implement a SSRF attack. If an attacker tricks a client to connect to a malicious server, the server can make the client call any URL including internal resources which are not directly accessible by the attacker.",
        "version_interval": "4.7.0:4.8.0",
    }
]

examples_formatted = PromptTemplate(
    input_variables=["cve_description", "version_interval"],
    template="""

""",
)

prompt = FewShotPromptTemplate(
    prefix="Given the following CVE and its description, could you give me the version interval in which the fixing commit (the commit patching the vulnerability described in the CVE) most likely is? Please return the interval I should use in the following format: start:end. If you are unsure, make the interval larger in order to make sure the fixing commit is really in there. Return nothing but start:end. I will give you some examples:",
    examples=examples_data,
    example_prompt=examples_formatted,
    suffix="""Here is the CVE information:
    The CVE's description: {description}""",
)
