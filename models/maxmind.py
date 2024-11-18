import geoip2.models
from pydantic import BaseModel


class MMRecord(BaseModel):
    name: str | None
    geoname_id: int | None
    code: str | None = None

    def __cmp__(self, other):
        return self.__dict__ == other.__dict__

    def __hash__(self):
        return hash((self.name, self.geoname_id, self.code))


class MMLocation(BaseModel):
    accuracy_radius: int | None
    latitude: float | None
    longitude: float | None
    time_zone: str | None

    def __cmp__(self, other):
        return self.__dict__ == other.__dict__

    def __hash__(self):
        return hash((self.accuracy_radius, self.latitude, self.longitude, self.time_zone))


class MMCity(BaseModel):
    city: MMRecord
    location: MMLocation
    postal_code: str | None
    subdivisions: tuple[MMRecord, ...]
    continent: MMRecord
    country: MMRecord
    registered_country: MMRecord
    represented_country: MMRecord | None

    @classmethod
    def from_mm(cls, mm_city: geoip2.models.City):
        return cls(city=MMRecord(name=mm_city.city.name, geoname_id=mm_city.city.geoname_id),
            location=MMLocation(accuracy_radius=mm_city.location.accuracy_radius, latitude=mm_city.location.latitude,
                                longitude=mm_city.location.longitude, time_zone=mm_city.location.time_zone),
            postal_code=mm_city.postal.code, subdivisions=tuple(
                map(lambda s: MMRecord(name=s.name, geoname_id=s.geoname_id, code=s.iso_code), mm_city.subdivisions)),
            continent=MMRecord(name=mm_city.continent.name, geoname_id=mm_city.continent.geoname_id,
                               code=mm_city.continent.code),
            country=MMRecord(name=mm_city.country.name, geoname_id=mm_city.country.geoname_id,
                             code=mm_city.country.iso_code),
            registered_country=MMRecord(name=mm_city.registered_country.name,
                                        geoname_id=mm_city.registered_country.geoname_id,
                                        code=mm_city.registered_country.iso_code),
            represented_country=MMRecord(name=mm_city.represented_country.name,
                                         geoname_id=mm_city.represented_country.geoname_id,
                                         code=mm_city.represented_country.iso_code) if mm_city.represented_country else None)

    def __cmp__(self, other):
        return self.__dict__ == other.__dict__

    def __hash__(self):
        return hash((self.city, self.location, self.postal_code, self.subdivisions, self.continent, self.country,
                     self.registered_country, self.represented_country))


class MMResult(BaseModel):
    as_org: str
    maxmind: MMCity

    def __cmp__(self, other):
        return self.__dict__ == other.__dict__

    def __hash__(self):
        return hash((self.as_org, self.maxmind))
