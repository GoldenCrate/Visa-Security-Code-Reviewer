from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    anthropic_api_key: str = ""
    database_url: str = "sqlite:///./app.db"
    mins_per_finding: float = 15.0
    claude_model: str = "claude-haiku-4-5"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
