### SonarQube Community Edition Rules Extractor

This script extracts information about all available rules from SonarQube Community Edition and saves them to a JSON,
which can be used to determine which rules should be filtered out during the analysis
of `gitextractor.SonarQubeRulesRepo`.

Example usage:
```sh
python3 extract_sonarqube_available_rules.py --api-url 'http://sonarqube:9000/' --release-date '2023-03-16' --existing-available-rules-path misc/community_edition_rule_keys.json
```  