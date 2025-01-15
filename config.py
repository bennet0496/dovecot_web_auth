from typing import Tuple, Type, List, Dict, Any

from pydantic import BaseModel
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource, )


class Database(BaseModel):
    dsn : str
    # host : str = "localhost"
    # user : str
    # password : str
    # port : int = 3306
    # db : str

class Ldap(BaseModel):
    host : str = "localhost"
    bind : str | None = None
    password : str | None = None
    port : int | None = None
    tls : bool = False
    tls_cert : str | None = None
    basedn : str


class MaxMind(BaseModel):
    city: str
    asn: str
    country: str | None = None


class AuditLists(BaseModel):
    ip_networks: str | None = None
    reverse_hostname: str | None = None

    network_name: str | None = None
    network_cc: str | None = None

    entities: str | None = None

    as_numbers: str | None = None
    as_names: str | None = None
    as_cc: str | None = None

    geo_location_ids: str | None = None
    coordinates: str | None = None


class Audit(BaseModel):
    disabled_services : List[str] | None = None
    ignore_networks : List[str] | None = None
    audit_result_success : str
    audit_process_unknown : bool = False
    log_local : bool = True
    local_locationname: str = "local network"
    local_networks: Dict[str, str] | None = None
    cache_ttl : int = 60 * 60 * 24
    db_authlog_dd_hash_bucket : int = 60
    db_authlog_dd_per_login: int = 5
    maxmind: MaxMind | None = None
    lists: AuditLists | None = None


class Cache(BaseModel):
    mode : str = "redis"
    host : str = "localhost"
    port : int = 6379


# noinspection PyDataclass
class Auth(BaseModel):
    disallow_passwords_from: List[str] = []

class EnvSettings(BaseSettings):
    config_path: str = "config.toml"

    model_config = SettingsConfigDict()

    @classmethod
    def settings_customise_sources(
            cls,
            settings_cls: Type[BaseSettings],
            init_settings: PydanticBaseSettingsSource,
            env_settings: PydanticBaseSettingsSource,
            dotenv_settings: PydanticBaseSettingsSource,
            file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (env_settings,)


# noinspection PyDataclass
class LogConfig(BaseSettings):
    version: int = 1
    disable_existing_loggers: bool = True
    formatters: dict[str, dict[str, str]] = {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(asctime)s %(name)-30.30s [%(levelname)5.5s] %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",

        }
    }
    handlers: dict[str, dict[str, str]] = {
        "stderr": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "stdout": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
    }
    loggers: dict[str, dict[str, Any]] = {
        "dovecot_web_auth": {"handlers": ["stdout"], "level": "INFO"},
        "fastapi": {"handlers": ["stderr"], "level": "INFO"},
        "uvicorn.access": {"handlers": ["stdout"], "level": "INFO"},
        "uvicorn.error": {"handlers": ["stderr"], "level": "INFO"},
        "uvicorn.asgi": {"handlers": ["stdout"], "level": "INFO"},
        "sqlalchemy": {"handlers": ["stderr"], "level": "ERROR"},
        "ipwhois": {"handlers": ["stdout"], "level": "INFO"},
    }

class Settings(BaseSettings):
    database: Database
    ldap: Ldap
    cache: Cache = Cache()
    audit: Audit
    auth: Auth | None = None
    log: LogConfig = LogConfig()

    model_config = SettingsConfigDict(toml_file=EnvSettings().config_path)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (TomlConfigSettingsSource(settings_cls),)