from typing import Any, List

import pytest
from langchain_core.language_models.llms import LLM
from langchain_google_vertexai import ChatVertexAI
from langchain_mistralai import ChatMistralAI
from langchain_openai import ChatOpenAI
from requests_cache import Optional

from llm.llm_service import LLMService  # this is a singleton
from llm.models.gemini import Gemini
from llm.models.mistral import Mistral
from llm.models.openai import OpenAI
from util.singleton import Singleton


# Mock the llm_service configuration object
class Config:
    type: str = None
    model_name: str = None
    temperature: str = None
    ai_core_sk: str = None

    def __init__(self, type, model_name, temperature, ai_core_sk):
        self.type = type
        self.model_name = model_name
        self.temperature = temperature
        self.ai_core_sk = ai_core_sk


@pytest.fixture(autouse=True)
def reset_singletons():
    # Clean up singleton instances after each test
    Singleton._instances = {}


@pytest.fixture(autouse=True)
def mock_environment_variables():
    mp = pytest.MonkeyPatch()
    mp.setenv("GPT_4_URL", "https://deployment.url.com")
    mp.setenv("MISTRAL_LARGE_URL", "https://deployment.url.com")
    mp.setenv("GEMINI_1.0_PRO_URL", "https://deployment.url.com")
    mp.setenv("OPENAI_API_KEY", "https://deployment.url.com")
    mp.setenv("GOOGLE_API_KEY", "https://deployment.url.com")
    mp.setenv("MISTRAL_API_KEY", "https://deployment.url.com")


class TestModel:
    def test_sap_gpt_instantiation(self):
        config = Config("sap", "gpt-4", 0.0, "example.json")
        llm_service = LLMService(config)
        assert isinstance(llm_service.model, OpenAI)

    def test_sap_gemini_instantiation(self):
        config = Config("sap", "gemini-1.0-pro", 0.0, "example.json")
        llm_service = LLMService(config)
        assert isinstance(llm_service.model, Gemini)

    def test_sap_mistral_instantiation(self):
        config = Config("sap", "mistral-large", 0.0, "example.json")
        llm_service = LLMService(config)
        assert isinstance(llm_service.model, Mistral)

    def test_gpt_instantiation(self):
        config = Config("third_party", "gpt-4", 0.0, "example.json")
        llm_service = LLMService(config)
        assert isinstance(llm_service.model, ChatOpenAI)

    # Google throws an error on creation, when no account is found
    # def test_gemini_instantiation(self):
    #     config = Config("third_party", "gemini-pro", 0.0, "example.json")
    #     llm_service = LLMService(config)
    #     assert isinstance(llm_service.model, ChatVertexAI)

    def test_mistral_instantiation(self):
        config = Config("third_party", "mistral-large-latest", 0.0, "example.json")
        llm_service = LLMService(config)
        assert isinstance(llm_service.model, ChatMistralAI)

    def test_singleton_instance_creation(self):
        """A second instantiation should return the exisiting instance."""
        config = Config("sap", "gpt-4", 0.0, "example.json")
        llm_service = LLMService(config)
        same_service = LLMService(config)
        assert (
            llm_service is same_service
        ), "LLMService should return the same instance."

    def test_singleton_same_instance(self):
        """A second instantiation with different parameters should return the existing instance unchanged."""
        config = Config("sap", "gpt-4", 0.0, "example.json")
        llm_service = LLMService(config)
        config = Config(
            "sap", "gpt-35-turbo", 0.0, "example.json"
        )  # This instantiation should not work, but instead return the already existing instance
        same_service = LLMService(config)
        assert llm_service is same_service
        assert llm_service.model.model_name == "gpt-4"

    def test_singleton_retains_state(self):
        """Reassigning a field variable of the instance should be allowed and reflected
        across instantiations."""
        config = Config("sap", "gpt-4", 0.0, "example.json")
        service = LLMService(config)

        service.model = OpenAI(
            model_name="gpt-35-turbo",
            deployment_url="deployment_url_placeholder",
            temperature=0.7,
            ai_core_sk_filepath="example.json",
        )
        same_service = LLMService(config)

        assert same_service.model == OpenAI(
            model_name="gpt-35-turbo",
            deployment_url="deployment_url_placeholder",
            temperature=0.7,
            ai_core_sk_filepath="example.json",
        ), "LLMService should retain state between instantiations"

    def test_reuse_singleton_without_config(self):
        config = Config("sap", "gpt-4", 0.0, "example.json")
        service = LLMService(config)

        same_service = LLMService()

        assert service is same_service

    def test_fail_first_instantiation_without_config(self):
        with pytest.raises(Exception):
            LLMService()
