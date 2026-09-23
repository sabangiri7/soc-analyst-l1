"""
Central configuration, loaded from environment / .env file.
Nothing here talks to the network - just settings.
"""
import os
from dotenv import load_dotenv

load_dotenv()


def _bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


class Config:
    # LLM backend. Options: anthropic | openai | google | mock
    #   openai = any OpenAI-compatible /chat/completions endpoint (OpenAI,
    #            OpenRouter, Ollama, vLLM, LM Studio, DeepSeek, ...) - point
    #            OPENAI_BASE_URL at it.
    #   mock   = deterministic offline provider for dev/CI with no API key.
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "anthropic")

    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "")  # "" -> falls back to AGENT_MODEL

    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "")  # "" -> falls back to AGENT_MODEL

    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY", "")
    GOOGLE_MODEL = os.getenv("GOOGLE_MODEL", "")  # "" -> falls back to AGENT_MODEL

    # FreeLLMAPI - one unified key for many free LLM providers behind a single
    # OpenAI-compatible gateway (https://freellmapi.co, self-hostable).
    # LLM_PROVIDER=freellmapi uses these. The gateway handles routing/fallover;
    # FREELLMAPI_MODEL=auto (default) lets it pick the best model per request.
    FREELLMAPI_API_KEY = os.getenv("FREELLMAPI_API_KEY", "")
    FREELLMAPI_BASE_URL = os.getenv("FREELLMAPI_BASE_URL", "http://localhost:3001/v1")
    FREELLMAPI_MODEL = os.getenv("FREELLMAPI_MODEL", "auto")

    # Generic default model - used by any provider that doesn't set its own
    # <PROVIDER>_MODEL.
    AGENT_MODEL = os.getenv("AGENT_MODEL", "claude-sonnet-4-6")

    # Splunk
    SPLUNK_HOST = os.getenv("SPLUNK_HOST", "")
    SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
    SPLUNK_VERIFY_SSL = _bool("SPLUNK_VERIFY_SSL", True)
    SPLUNK_SEARCH = os.getenv("SPLUNK_SEARCH", "search index=notable status=new | head 20")

    # CrowdStrike
    FALCON_CLIENT_ID = os.getenv("FALCON_CLIENT_ID", "")
    FALCON_CLIENT_SECRET = os.getenv("FALCON_CLIENT_SECRET", "")
    FALCON_BASE_URL = os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com")

    # Agent behavior / guardrails
    AUTO_CLOSE_CONFIDENCE_THRESHOLD = float(os.getenv("AUTO_CLOSE_CONFIDENCE_THRESHOLD", "0.9"))
    DRY_RUN_ACTIONS = _bool("DRY_RUN_ACTIONS", True)
    # Use mock Splunk/CrowdStrike connectors instead of live APIs - for testing
    # the agent + RAG + self-improvement loop before wiring real credentials.
    MOCK_MODE = _bool("MOCK_MODE", False)

    # --- SIEM platform (alert source) ---
    # Which SIEM platform to pull alerts from: splunk | qradar | elastic |
    # sentinel | wazuh | mock. Additional connections can be added at runtime
    # through the dashboard (data/siem_providers.json) - see siem_providers.py.
    SIEM_PROVIDER = os.getenv("SIEM_PROVIDER", "splunk")

    # Splunk (also configurable per-provider via the dashboard)
    SPLUNK_HOST = os.getenv("SPLUNK_HOST", "")
    SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
    SPLUNK_VERIFY_SSL = _bool("SPLUNK_VERIFY_SSL", True)
    SPLUNK_SEARCH = os.getenv("SPLUNK_SEARCH", "search index=notable status=new | head 20")

    # IBM QRadar
    QRADAR_HOST = os.getenv("QRADAR_HOST", "")
    QRADAR_TOKEN = os.getenv("QRADAR_TOKEN", "")
    QRADAR_VERIFY_SSL = _bool("QRADAR_VERIFY_SSL", True)
    QRADAR_SEARCH = os.getenv("QRADAR_SEARCH", "SELECT * FROM events LAST 1 HOUR")

    # Elastic Security
    ELASTIC_HOST = os.getenv("ELASTIC_HOST", "")
    ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")
    ELASTIC_VERIFY_SSL = _bool("ELASTIC_VERIFY_SSL", True)
    ELASTIC_INDEX = os.getenv("ELASTIC_INDEX", ".siem-signals-*")

    # Microsoft Sentinel
    SENTINEL_TENANT_ID = os.getenv("SENTINEL_TENANT_ID", "")
    SENTINEL_CLIENT_ID = os.getenv("SENTINEL_CLIENT_ID", "")
    SENTINEL_CLIENT_SECRET = os.getenv("SENTINEL_CLIENT_SECRET", "")
    SENTINEL_WORKSPACE_ID = os.getenv("SENTINEL_WORKSPACE_ID", "")
    SENTINEL_QUERY = os.getenv("SENTINEL_QUERY", "")

    # Wazuh (indexer / OpenSearch API) - docker deployment lives in wazuh/
    # on localhost:9200 with default admin/admin credentials.
    WAZUH_HOST = os.getenv("WAZUH_HOST", "")
    WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "admin")
    WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "admin")
    WAZUH_INDEX = os.getenv("WAZUH_INDEX", "wazuh-alerts-*")
    WAZUH_RELATED_INDEX = os.getenv("WAZUH_RELATED_INDEX", "wazuh-archives-*")
    WAZUH_VERIFY_SSL = _bool("WAZUH_VERIFY_SSL", False)  # self-signed by default
    WAZUH_CA_CERT = os.getenv("WAZUH_CA_CERT", "")

    # Mock SIEM (SIEM_PROVIDER=mock) - optional override for the canned alerts
    MOCK_SIEM_ALERTS_FILE = os.getenv("MOCK_SIEM_ALERTS_FILE", "")

    # Where the dashboard stores extra SIEM provider connections (JSON list)
    SIEM_PROVIDERS_PATH = os.getenv("SIEM_PROVIDERS_PATH", "./data/siem_providers.json")

    # Storage
    CHROMA_DB_PATH = os.getenv("CHROMA_DB_PATH", "./data/chroma")
    FEEDBACK_LOG_PATH = os.getenv("FEEDBACK_LOG_PATH", "./data/feedback_log.jsonl")


cfg = Config()
