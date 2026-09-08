import os
import time
import datetime
import json
from dataclasses import dataclass

import requests
import tiktoken
from urllib.parse import urlparse

from hackingBuddyGPT.utils.configurable import configurable, parameter
from hackingBuddyGPT.utils.llm_util import LLM, LLMResult

# Per-process request throttle (seconds between consecutive API calls).
# Configure via LLM_MIN_INTERVAL_SECONDS (or LLM_MIN_INTERVAL_MS). 0 disables throttling.
_LAST_REQUEST_AT = 0.0


@configurable("openai-compatible-llm-api", "OpenAI-compatible LLM API")
@dataclass
class OpenAIConnection(LLM):
    """
    While the OpenAIConnection is a configurable, it is not exported by this packages __init__.py on purpose. This is
    due to the fact, that it usually makes more sense for a finished UseCase to specialize onto one specific version of
    an OpenAI API compatible LLM.
    If you really must use it, you can import it directly from the utils.openai.openai_llm module, which will later on
    show you, that you did not specialize yet.
    """

    api_key: str = parameter(desc="OpenAI API Key", secret=True)
    model: str = parameter(desc="OpenAI model name")
    context_size: int = parameter(
        desc="Maximum context size for the model, only used internally for things like trimming to the context size"
    )
    api_url: str = parameter(desc="URL of the OpenAI API", default="https://api.openai.com")
    api_path: str = parameter(desc="Path to the OpenAI API", default="/v1/chat/completions")
    api_timeout: int = parameter(desc="Timeout for the API request", default=240)
    api_backoff: int = parameter(desc="Backoff time in seconds when running into rate-limits", default=60)
    api_retries: int = parameter(desc="Number of retries when running into rate-limits", default=3)
    temperature: float = parameter(desc="Sampling temperature", default=0.0)

    def get_response(self, prompt, *, retry: int = 0,azure_retry: int = 0, **kwargs) -> LLMResult:
        if retry >= self.api_retries:
            raise Exception("Failed to get response from OpenAI API")

        if hasattr(prompt, "render"):
            prompt = prompt.render(**kwargs)

        if urlparse(self.api_url).hostname and urlparse(self.api_url).hostname.endswith(".azure.com"):
            # azure ai header
            headers = {"api-key": f"{self.api_key}"}
        else:
            # normal header
            headers = {"Authorization": f"Bearer {self.api_key}"}

        # Route to Responses API when api_path points to /v1/responses or when the
        # model is a GPT-5 family model. Some OpenAI-compatible gateways only support
        # GPT-5 through streaming chat/completions, so allow an explicit override.
        force_chat_completions = os.environ.get("CPA_API_FORCE_CHAT_COMPLETIONS", "").lower() in ("1", "true", "yes")
        stream_chat_completions = os.environ.get("CPA_API_STREAM", "").lower() in ("1", "true", "yes")
        use_responses_api = (("responses" in self.api_path) or self.model.startswith("gpt-5")) and not force_chat_completions

        if use_responses_api:
            data = {"model": self.model, "input": [{"role": "user", "content": prompt}], "temperature": self.temperature}
            # Auto-swap path when caller left it as chat/completions but model is GPT-5.
            effective_path = self.api_path if "responses" in self.api_path else "/v1/responses"
        else:
            data = {"model": self.model, "messages": [{"role": "user", "content": prompt}], "temperature": self.temperature}
            if stream_chat_completions:
                data["stream"] = True
            effective_path = self.api_path

        # Optional per-process request throttle (prevents overwhelming proxy rate limits).
        global _LAST_REQUEST_AT
        min_interval = float(
            os.environ.get("LLM_MIN_INTERVAL_SECONDS")
            or (float(os.environ.get("LLM_MIN_INTERVAL_MS", "0")) / 1000.0)
            or 0
        )
        if min_interval > 0:
            elapsed = time.time() - _LAST_REQUEST_AT
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
        _LAST_REQUEST_AT = time.time()

        # Allow env var override of per-HTTP-call timeout (default 240s is often
        # too tight for GPT-5 reasoning). Set CPA_API_TIMEOUT to extend.
        effective_timeout = int(os.environ.get("CPA_API_TIMEOUT", self.api_timeout))

        try:
            tic = datetime.datetime.now()
            response = requests.post(
                f'{self.api_url}{effective_path}',
                headers=headers,
                json=data,
                timeout=effective_timeout,
                stream=stream_chat_completions and not use_responses_api,
            )

            if response.status_code == 429:
                print(f"[RestAPI-Connector] running into rate-limits, waiting for {self.api_backoff} seconds")
                time.sleep(self.api_backoff)
                return self.get_response(prompt, retry=retry + 1)

            if response.status_code == 408:
                if azure_retry < self.api_retries:
                    print("Received 408 Status Code, trying again.")
                    return self.get_response(prompt, azure_retry = azure_retry + 1)
                else:
                    raise Exception(f"Error from Gateway ({response.status_code})")

            # Retry on server errors (500, 502, 503, 504)
            if response.status_code in (500, 502, 503, 504):
                backoff = min(10 * (retry + 1), 60)
                print(f"[RestAPI-Connector] Server error {response.status_code}, retrying in {backoff}s (attempt {retry + 1}/{self.api_retries})")
                time.sleep(backoff)
                return self.get_response(prompt, retry=retry + 1)

            if response.status_code != 200:
                body = response.text.strip().replace("\n", " ")
                if len(body) > 500:
                    body = body[:500] + "..."
                raise Exception(f"Error from OpenAI Gateway ({response.status_code}): {body}")

        except requests.exceptions.ConnectionError:
            print("Connection error! Retrying in 5 seconds..")
            time.sleep(5)
            return self.get_response(prompt, retry=retry + 1)

        except requests.exceptions.Timeout:
            print("Timeout while contacting LLM REST endpoint")
            return self.get_response(prompt, retry=retry + 1)

        if stream_chat_completions and not use_responses_api:
            result = ""
            tok_query = 0
            tok_res = 0
            for line in response.iter_lines(decode_unicode=True):
                if not line or not line.startswith("data:"):
                    continue
                payload = line[len("data:"):].strip()
                if payload == "[DONE]":
                    break
                try:
                    chunk = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                usage = chunk.get("usage") or {}
                tok_query = usage.get("prompt_tokens", tok_query)
                tok_res = usage.get("completion_tokens", tok_res)
                for choice in chunk.get("choices", []):
                    delta = choice.get("delta") or {}
                    result += delta.get("content") or delta.get("reasoning_content") or ""
            if not result:
                raise Exception("Empty response from streaming chat/completions")
        else:
            # now extract the JSON status message
            response = response.json()

            if use_responses_api:
                # Responses API schema:
                #   response.output = [ {type:"message", content:[ {type:"output_text", text:"..."} ]}, ... ]
                # Pick the first message-type output block and concatenate its output_text segments.
                result = ""
                for block in response.get("output", []):
                    if block.get("type") != "message":
                        continue
                    for seg in block.get("content", []):
                        if seg.get("type") == "output_text" and seg.get("text"):
                            result += seg["text"]
                    if result:
                        break
                if not result:
                    raise Exception(f"Empty response from Responses API: keys={list(response.keys())}")
                usage = response.get("usage", {}) or {}
                tok_query = usage.get("input_tokens", 0)
                tok_res = usage.get("output_tokens", 0)
            else:
                message = response["choices"][0]["message"]
                result = message.get("content") or ""
                # Fallback: some models (e.g. GPT-5.x via proxy) return content=null
                # with actual text in reasoning_content or refusal fields
                if not result:
                    result = message.get("reasoning_content") or message.get("refusal") or ""
                if not result:
                    raise Exception(f"Empty response from model: content=null, message keys={list(message.keys())}")
                tok_query = response.get("usage", {}).get("prompt_tokens", 0)
                tok_res = response.get("usage", {}).get("completion_tokens", 0)

        if not tok_query or not tok_res:
            try:
                enc = tiktoken.encoding_for_model(self.model)
            except KeyError:
                enc = tiktoken.get_encoding("cl100k_base")
            tok_query = tok_query or len(enc.encode(prompt))
            tok_res = tok_res or len(enc.encode(result))
        duration = datetime.datetime.now() - tic

        return LLMResult(result, prompt, result, duration, tok_query, tok_res)

    def encode(self, query) -> list[int]:
        # Use tiktoken for known models, fallback to cl100k_base for others
        try:
            encoding = tiktoken.encoding_for_model(self.model)
        except KeyError:
            encoding = tiktoken.get_encoding("cl100k_base")
        return encoding.encode(query)

@configurable("openai/gpt-3.5-turbo", "OpenAI GPT-3.5 Turbo")
@dataclass
class GPT35Turbo(OpenAIConnection):
    model: str = "gpt-3.5-turbo"
    context_size: int = 16385


@configurable("openai/gpt-4", "OpenAI GPT-4")
@dataclass
class GPT4(OpenAIConnection):
    model: str = "gpt-4"
    context_size: int = 8192


@configurable("openai/gpt-4-turbo", "OpenAI GPT-4-turbo (preview)")
@dataclass
class GPT4Turbo(OpenAIConnection):
    model: str = "gpt-4-turbo-preview"
    context_size: int = 128000


@configurable("openai/gpt-4o", "OpenAI GPT-4o")
@dataclass
class GPT4oMini(OpenAIConnection):
    model: str = "gpt-4o"
    context_size: int = 128000


@configurable("openai/gpt-4o-mini", "OpenAI GPT-4o-mini")
@dataclass
class GPT4oMini(OpenAIConnection):
    model: str = "gpt-4o-mini"
    context_size: int = 128000


@configurable("openai/o1-preview", "OpenAI o1-preview")
@dataclass
class O1Preview(OpenAIConnection):
    model: str = "o1-preview"
    context_size: int = 128000


@configurable("openai/o1-mini", "OpenAI o1-mini")
@dataclass
class O1Mini(OpenAIConnection):
    model: str = "o1-mini"
    context_size: int = 128000
