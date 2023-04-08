import json

MAPPING_FILE = 'owasp2021_cwe_mapping.json'


def get_short_category(owasp_id: str) -> str:
    return owasp_id.split(' - ')[0]


class OwaspCweMapper:
    def __init__(self, file_name: str = MAPPING_FILE):
        self.mapping_file = open(file_name, 'r')
        self.owasp_cwe_mapping = json.load(self.mapping_file)

    def fetch_mapping(self, cwe_id: str) -> str | None:
        for owasp_id, cwe_ids in self.owasp_cwe_mapping.items():
            if cwe_id in cwe_ids:
                return owasp_id
        return None

    def fetch_short_mapping(self, cwe_id: str) -> str | None:
        owasp_id = self.fetch_mapping(cwe_id)
        if owasp_id:
            return get_short_category(owasp_id)
        return None

    def close(self):
        if self.mapping_file:
            self.mapping_file.close()
            self.mapping_file = None
