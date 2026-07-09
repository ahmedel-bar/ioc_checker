"""
config.py

Centralized configuration loading for the IOC Checker CLI.
Loads API keys and runtime settings from a .env file using python-dotenv.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

# Load environment variables from .env file in the current working directory
load_dotenv()

VERSION: str = "1.0.0"
REQUEST_TIMEOUT: int = 15  # seconds, used by all provider HTTP calls


@dataclass(frozen=True)
class ProviderConfig:
    """Holds the name, API key, and env var name for a single provider."""

    display_name: str
    env_var: str
    api_key: str | None
    requires_key: bool = True  # some providers (URLhaus, MalwareBazaar) are public

    @property
    def is_configured(self) -> bool:
        if not self.requires_key:
            return True
        return bool(self.api_key)


@dataclass(frozen=True)
class AppConfig:
    """Aggregate application configuration."""

    virustotal: ProviderConfig
    otx: ProviderConfig
    threatfox: ProviderConfig
    abuseipdb: ProviderConfig
    urlhaus: ProviderConfig
    malwarebazaar: ProviderConfig
    pulsedive: ProviderConfig

    def all_providers(self) -> list[ProviderConfig]:
        return [
            self.virustotal,
            self.otx,
            self.threatfox,
            self.abuseipdb,
            self.urlhaus,
            self.malwarebazaar,
            self.pulsedive,
        ]


def load_config() -> AppConfig:
    """Build an AppConfig instance from environment variables."""
    return AppConfig(
        virustotal=ProviderConfig(
            display_name="VirusTotal",
            env_var="VT_API_KEY",
            api_key=os.getenv("VT_API_KEY") or None,
        ),
        otx=ProviderConfig(
            display_name="AlienVault OTX",
            env_var="OTX_API_KEY",
            api_key=os.getenv("OTX_API_KEY") or None,
        ),
        threatfox=ProviderConfig(
            display_name="ThreatFox",
            env_var="THREATFOX_API_KEY",
            api_key=os.getenv("THREATFOX_API_KEY") or None,
        ),
        abuseipdb=ProviderConfig(
            display_name="AbuseIPDB",
            env_var="ABUSEIPDB_API_KEY",
            api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
        ),
        urlhaus=ProviderConfig(
            display_name="URLhaus",
            env_var="URLHAUS_API_KEY",
            api_key=os.getenv("URLHAUS_API_KEY") or None,
            requires_key=False,
        ),
        malwarebazaar=ProviderConfig(
            display_name="MalwareBazaar",
            env_var="MALWAREBAZAAR_API_KEY",
            api_key=os.getenv("MALWAREBAZAAR_API_KEY") or None,
            requires_key=False,
        ),
        pulsedive=ProviderConfig(
            display_name="Pulsedive",
            env_var="PULSEDIVE_API_KEY",
            api_key=os.getenv("PULSEDIVE_API_KEY") or None,
        ),
    )
