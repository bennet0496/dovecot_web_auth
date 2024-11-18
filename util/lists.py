import os.path

from config import Settings


class Manager:
    def __init__(self, settings: Settings):
        self.ip_networks = set()
        self.reverse_hostname = set()
        self.network_name = set()
        self.network_cc = set()
        self.entities = set()
        self.as_numbers = set()
        self.as_names = set()
        self.as_cc = set()
        self.geo_location_ids = set()
        self.coordinates = set()
        self.settings = settings
        for key, value in settings.audit.lists.model_dump().items():
            if value is not None and os.path.isfile(value):
                with open(value, 'r') as f:
                    data = [line for line in map(lambda x: x.strip(), f.readlines()) if
                            not line.isspace() and not len(line) == 0 and not line.startswith('#')]
                    setattr(self, key, set(data))
            else:
                setattr(self, key, set())
