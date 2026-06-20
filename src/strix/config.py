from __future__ import annotations

from pathlib import Path

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

from strix.logging import register_secret


def _config_path() -> Path:
    """Locate config.yaml: prefer the current working directory, fall back to repo root."""
    cwd_cfg = Path.cwd() / "config.yaml"
    if cwd_cfg.exists():
        return cwd_cfg
    return Path(__file__).resolve().parents[2] / "config.yaml"


class Settings(BaseSettings):
    """Typed configuration.

    Defaults come from ``config.yaml``; environment variables / ``.env`` override them.
    """

    app_name: str = "STRIX"
    version: str = "0.1.0"
    max_concurrency: int = 5
    default_output_dir: str = "./output"
    default_formats: list[str] = ["json", "md", "html"]
    acknowledged_authorization: bool = False
    log_level: str = "INFO"
    rate_limits: dict[str, float] = {}

    # Optional API keys (from environment / .env). STRIX runs without them.
    shodan_api_key: str | None = None
    virustotal_api_key: str | None = None
    ipinfo_token: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        yaml_file=str(_config_path()),
        extra="ignore",
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # Priority (high -> low): init > env > .env > config.yaml > file secrets.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )

    def rate_limit_for(self, module: str, default: float = 1.0) -> float:
        """Return the configured rate limit (seconds) for a module, or a default."""
        return self.rate_limits.get(module, default)


settings = Settings()

# Register any secret values so the logging layer can redact them.
for _secret in (settings.shodan_api_key, settings.virustotal_api_key, settings.ipinfo_token):
    register_secret(_secret)
