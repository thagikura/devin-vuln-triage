from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    devin_api_token: str = ""
    devin_org_id: str = ""
    devin_api_base_url: str = "https://api.devin.ai/v3"

    github_token: str = ""
    github_webhook_secret: str = ""
    target_repo: str = "thagikura/superset-fork"

    database_url: str = "sqlite:///data/triage.db"

    poll_interval_seconds: int = 30
    session_timeout_seconds: int = 1800  # 30 minutes

    model_config = {"env_file": ".env"}


settings = Settings()
