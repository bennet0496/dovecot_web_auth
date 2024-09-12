from typing import Tuple, Type, List, Dict

from pydantic import BaseModel

from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    TomlConfigSettingsSource, CliSettingsSource,
)

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
    city: str | None = None
    asn: str | None = None
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
    local_locationname: str | None = None
    local_networks: Dict[str, str] | None = None
    maxmind: MaxMind | None = None
    lists: AuditLists | None = None


class Cache(BaseModel):
    mode : str = "redis"
    host : str
    port : int = 6379

class EnvSettings(BaseSettings):
    config_path: str

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

class Settings(BaseSettings):
    database: Database
    ldap: Ldap
    cache: Cache
    audit: Audit

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