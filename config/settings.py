#!/usr/bin/env python3
import os
import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class Settings:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def __init__(self):
        if self._loaded:
            return
        self._loaded = True
        self._config = self._load_config()

    def _load_config(self):
        config_path = Path(__file__).parent / "config.yaml"
        if not config_path.exists():
            logger.warning(f"Config file not found at {config_path}, using defaults")
            return {}
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        self._apply_env_overrides(config)
        return config

    def _apply_env_overrides(self, config):
        api_keys = {
            "virustotal": "VT_API_KEY",
            "urlscan": "URLSCAN_API_KEY",
            "abuseipdb": "ABUSEIPDB_API_KEY",
            "alienvault_otx": "OTX_API_KEY",
        }
        intel = config.get("threat_intel", {})
        for service, env_var in api_keys.items():
            env_val = os.getenv(env_var)
            if env_val and service in intel:
                intel[service]["api_key"] = env_val
        secret = os.getenv("SOC_SECRET_KEY")
        if secret:
            config.setdefault("app", {})["secret_key"] = secret

    def get(self, *keys, default=None):
        val = self._config
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return default
        return val if val is not None else default

settings = Settings()
