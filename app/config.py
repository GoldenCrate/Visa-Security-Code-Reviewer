from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    anthropic_api_key: str = ""
    database_url: str = "sqlite:///./app.db"
    mins_per_finding: float = 15.0
    claude_model: str = "claude-haiku-4-5"
    # When true, seed synthetic demo data on startup if the DB is empty
    # (used on the public demo deploy; off for local/dev/tests).
    seed_demo: bool = False

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
