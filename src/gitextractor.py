import copy
import json
import logging
import re
import shutil
import tempfile
from pathlib import PurePath
from typing import List

import git
import yaml
from globmatch import glob_match

from misc.extract_sonarqube_available_rules import AvailableRuleKeys


class RawSecurityRule:
    def __init__(self, blob: git.Blob):
        self.path = blob.path
        self.raw_data = blob.data_stream.read().decode('utf-8')
        self.metadata = {}
        self.id = None


class GitSecurityRulesRepo:
    """
    A wrapper for a git repository containing security rules.
    """

    def __init__(self, repo_upstream: str, rules_glob: List[str]):
        self.repo_upstream = repo_upstream
        self.repo_name = repo_upstream.split('/')[-1]
        self.cloned_repo_path = self._get_tmp_repo_path(self.repo_name)
        self.repo = git.Repo.clone_from(repo_upstream, self.cloned_repo_path)
        self.latest_commit = self.repo.head.commit.hexsha
        self.raw_rules = self.get_raw_rules(rules_glob)
        self.update_raw_rules_metadata()
        self.update_raw_rules_ids()

    def __del__(self):
        self.repo.close()
        shutil.rmtree(self.cloned_repo_path)

    @staticmethod
    def _get_tmp_repo_path(repo_name: str):
        return tempfile.mkdtemp(prefix='{}-'.format(repo_name))

    def get_raw_rules(self, rules_glob: List[str]) -> List[RawSecurityRule]:
        raw_rules = []
        for blob in self.repo.tree().traverse(visit_once=True):
            if glob_match(blob.path, rules_glob):
                raw_rules.append(RawSecurityRule(blob))
        return raw_rules

    def update_raw_rules_ids(self):
        pass

    def update_raw_rules_metadata(self):
        pass


class SonarQubeRulesRepo(GitSecurityRulesRepo):
    def __init__(self, extracted_available_rule_keys: AvailableRuleKeys = None):
        self.available_rule_keys = extracted_available_rule_keys
        super().__init__('https://github.com/SonarSource/rspec', ['rules/**/metadata.json'])
        if self.available_rule_keys:  # filter out unavailable rules after rule ids are updated
            self.raw_rules = self.filter_available_rules(self.raw_rules, self.available_rule_keys)

    @staticmethod
    def filter_security_rules(raw_rules: List[RawSecurityRule]) -> List[RawSecurityRule]:
        return [rule for rule in raw_rules if
                rule.metadata['type'] in ['SECURITY_HOTSPOT', 'VULNERABILITY'] and rule.metadata['status'] in ['ready',
                                                                                                               'beta']]

    @staticmethod
    def filter_available_rules(raw_rules: List[RawSecurityRule], available_rule_keys: AvailableRuleKeys) -> \
            List[RawSecurityRule]:
        return [rule for rule in raw_rules if rule.id in available_rule_keys]

    def update_raw_rules_ids(self):
        for raw_rule in self.raw_rules:
            raw_rule_dir = PurePath(raw_rule.path).parent
            raw_rule_language = raw_rule_dir.parts[-1]
            raw_rule_sqkey = raw_rule_dir.parts[-2]
            raw_rule_key = f'{raw_rule_language}:{raw_rule_sqkey}'
            raw_rule.id = raw_rule_key

    def update_raw_rules_metadata(self):
        parent_rules_metadata = {}
        new_raw_rules = []
        for raw_rule in self.raw_rules:
            try:
                raw_rule.metadata = json.loads(raw_rule.raw_data)
            except json.JSONDecodeError:
                logging.warning(f'Could not parse SonarQube query specification: {raw_rule.path}')
                continue
            if glob_match(raw_rule.path, ['rules/*/metadata.json']):
                parent_rules_metadata[raw_rule.path] = raw_rule.metadata
            else:
                new_raw_rules.append(raw_rule)
        for raw_rule in new_raw_rules:
            parent_rule_path = PurePath(raw_rule.path).parent.parent / 'metadata.json'
            new_raw_rule_metadata = copy.deepcopy(parent_rules_metadata[str(parent_rule_path)])
            new_raw_rule_metadata.update(raw_rule.metadata)  # language-specific metadata overrides general metadata
            raw_rule.metadata = new_raw_rule_metadata
        self.raw_rules = self.filter_security_rules(new_raw_rules)


class SemgrepRulesRepo(GitSecurityRulesRepo):
    def __init__(self):
        super().__init__('https://github.com/returntocorp/semgrep-rules',
                         ['**/security/**/*.y*ml', '**/audit/**/*.y*ml'])

    @staticmethod
    def is_yaml_lang_rule(raw_rule: RawSecurityRule) -> bool:
        return PurePath(raw_rule.path).parts[0] == 'yaml'

    @staticmethod
    def is_rule(raw_rule: RawSecurityRule) -> bool:
        return not raw_rule.path.endswith('.test.yaml') and not raw_rule.path.endswith('.test.yml')

    def update_raw_rules_ids(self):
        for raw_rule in self.raw_rules:
            rule_path_with_id = PurePath(raw_rule.path).with_suffix('') / raw_rule.metadata['id']
            raw_rule.id = '.'.join(rule_path_with_id.parts)

    def update_raw_rules_metadata(self):
        new_raw_rules = []
        for raw_rule in self.raw_rules:
            if not self.is_rule(raw_rule):
                continue
            if self.is_yaml_lang_rule(raw_rule):
                # ignore yaml language rules for now
                continue

            try:
                raw_rule.metadata = yaml.safe_load(raw_rule.raw_data)
            except yaml.YAMLError:
                logging.warning(f'Could not parse Semgrep rule metadata: {raw_rule.path}')
                continue

            # semgrep rules can have multiple rules with different metadata in one file, so we need to split them
            for sub_rule in raw_rule.metadata.get('rules', []):
                new_raw_rule = copy.deepcopy(raw_rule)
                new_raw_rule.metadata = copy.deepcopy(sub_rule)
                new_raw_rules.append(new_raw_rule)
        self.raw_rules = new_raw_rules


class CodeQLRulesRepo(GitSecurityRulesRepo):
    def __init__(self):
        super().__init__('https://github.com/github/codeql', ['**/ql/src/**/*.ql'])

    @staticmethod
    def is_rule(raw_rule: RawSecurityRule) -> bool:
        return 'id' in raw_rule.metadata and "count-untrusted-data-external-api" not in raw_rule.metadata['id']

    @staticmethod
    def filter_security_rules(raw_rules: List[RawSecurityRule]) -> List[RawSecurityRule]:
        return [rule for rule in raw_rules if
                not rule.metadata['id'].startswith('ql/') and 'security' in rule.metadata.get('tags', '').split()]

    @staticmethod
    def load_ql(ql_raw_data: str) -> dict:
        # extract metadata comment block without using "codeql resolve metadata"
        metadata_raw = re.search(r'(?s)/\*\*.*?\*/', ql_raw_data).group(0)
        metadata = {}
        for field in re.findall(r'@([a-zA-Z-.]+)(?:\s+([^@]+))?', metadata_raw):
            field_name, field_value = field
            # normalize field values by removing syntax elements
            field_value = re.sub(r'\s*\n\s*\*/?', ' ', field_value).strip()
            # remove multiple spaces
            field_value = re.sub(r'\s+', ' ', field_value)
            metadata[field_name] = field_value
        return metadata

    def update_raw_rules_ids(self):
        for raw_rule in self.raw_rules:
            raw_rule.id = raw_rule.metadata['id']

    def update_raw_rules_metadata(self):
        new_raw_rules = []
        for raw_rule in self.raw_rules:
            try:
                raw_rule.metadata = self.load_ql(raw_rule.raw_data)
            except Exception as e:
                logging.warning(f'Could not parse CodeQL query metadata: {raw_rule.path} {e}')

            if self.is_rule(raw_rule):
                new_raw_rules.append(raw_rule)
        self.raw_rules = self.filter_security_rules(new_raw_rules)


class JoernRulesRepo(GitSecurityRulesRepo):
    def __init__(self):
        super().__init__('https://github.com/joernio/joern', ['querydb/src/main/**/scanners/*/**/*.scala'])

    @staticmethod
    def load_scala(scala_raw_data: str) -> List[dict]:
        queries_metadata = []
        for raw_query in re.findall(r'@q\s+def\s+\w+\(.*\)\s*:\s*Query\s*=\s*Query\.make\([^@]*\)', scala_raw_data):
            metadata = {}
            # description can be multiline
            raw_query = raw_query.replace('"""', '"')
            for field in re.findall(r'(\w+)\s*=\s*s?(".*?"|\d+|List\(.*?\))', raw_query, re.IGNORECASE | re.DOTALL):
                field_name, field_value = field
                # normalize field values by removing syntax elements
                field_value = field_value.replace('|', '')
                field_value = re.sub(r'List\((.*)\)', r'\1', field_value.replace('QueryTags.', '')).strip('"')
                field_value = re.sub(r'\s*\n\s*\*/?', ' ', field_value).strip()
                field_value = re.sub(r'\s+', ' ', field_value)
                metadata[field_name] = field_value
            queries_metadata.append(metadata)
        return queries_metadata

    def update_raw_rules_ids(self):
        for raw_rule in self.raw_rules:
            raw_rule.id = raw_rule.metadata['name']

    def update_raw_rules_metadata(self):
        new_raw_rules = []
        for raw_rule in self.raw_rules:
            queries_metadata = []
            try:
                queries_metadata = self.load_scala(raw_rule.raw_data)
            except Exception as e:
                logging.warning(f'Could not parse Joern query metadata: {raw_rule.path} {e}')
            for query_metadata in queries_metadata:
                new_raw_rule = copy.deepcopy(raw_rule)
                new_raw_rule.metadata = query_metadata
                new_raw_rules.append(new_raw_rule)
        self.raw_rules = new_raw_rules
