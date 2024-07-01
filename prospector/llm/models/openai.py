from typing import Any, Dict, List, Optional

import requests
from langchain_core.language_models.llms import LLM

import llm.instantiation as instantiation
from log.logger import logger


class OpenAI(LLM):
    model_name: str
    deployment_url: str
    temperature: float
    ai_core_sk_filepath: str

    @property
    def _llm_type(self) -> str:
        return "SAP OpenAI"

    @property
    def _identifying_params(self) -> Dict[str, Any]:
        """Return a dictionary of identifying parameters."""
        return {
            "model_name": self.model_name,
            "deployment_url": self.deployment_url,
            "temperature": self.temperature,
            "ai_core_sk_filepath": self.ai_core_sk_filepath,
        }

    def _call(
        self, prompt: str, stop: Optional[List[str]] = None, **kwargs: Any
    ) -> str:
        endpoint = f"{self.deployment_url}/chat/completions?api-version=2023-05-15"
        headers = instantiation.get_headers(self.ai_core_sk_filepath)
        data = {
            "messages": [
                {
                    "role": "user",
                    "content": f"{prompt}",
                }
            ],
            "temperature": self.temperature,
        }

        try:
            response = requests.post(endpoint, headers=headers, json=data)

        except requests.exceptions.RequestException as e:
            logger.error(f"Invalid response from AI Core API with: {e}")
            raise Exception("Invalid response from AI Core API.")

        if (
            response.status_code == 400 and response.reason == "Bad Request"
        ):  # means that token length has been exceeded
            return "False"
        if response.status_code != 200:
            logger.error("The response from AI Core did not have status code 200.")
            raise Exception("AI Core response status code != 200.")

        return self.parse(response.json())

    def parse(self, message) -> str:
        """Parse the returned JSON object from OpenAI."""
        return message["choices"][0]["message"]["content"]
