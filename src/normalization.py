import contextlib
import logging
import re
from datetime import datetime
from pathlib import PurePath
from typing import List

from gitextractor import RawSecurityRule, GitSecurityRulesRepo, SonarQubeRulesRepo, SemgrepRulesRepo, CodeQLRulesRepo, \
    JoernRulesRepo
from models import ComparableRule
from owasp_cwe_mapping import OwaspCweMapper


class RuleEqualizer:
    def __init__(self):
        self.sonarqube_converter = SonarQubeRuleConverter()
        self.semgrep_converter = SemgrepRuleConverter()
        self.codeql_converter = CodeQLRuleConverter()
        self.joern_converter = JoernRuleConverter()

    def convert(self, rules_repo: GitSecurityRulesRepo) -> List[ComparableRule]:
        if isinstance(rules_repo, SonarQubeRulesRepo):
            rule_converter = self.sonarqube_converter
        elif isinstance(rules_repo, SemgrepRulesRepo):
            rule_converter = self.semgrep_converter
        elif isinstance(rules_repo, CodeQLRulesRepo):
            rule_converter = self.codeql_converter
        elif isinstance(rules_repo, JoernRulesRepo):
            rule_converter = self.joern_converter
        else:
            raise NotImplementedError
        return list(
            map(rule_converter.convert, rules_repo.raw_rules, [rules_repo.checkout_date] * len(rules_repo.raw_rules)))


class RuleConverter:
    def __init__(self, data_source: str):
        self.data_source = data_source
        pass

    @staticmethod
    def _upper_list(lst: List[str]) -> List[str]:
        return list(map(str.upper, lst))

    @staticmethod
    def _lower_list(lst: List[str]) -> List[str]:
        return list(map(str.lower, lst))

    @staticmethod
    def normalize_languages(languages: List[str]) -> List[str]:
        language_map = {
            # SonarQube doesn't distinguish between C and C++
            'c/c++': ['cpp', 'c++', 'c', 'cfamily'],
            # Joern and CodeQL don't distinguish between Java and Kotlin
            'kotlin/java': ['java', 'kotlin', 'kt', 'android'],
            # CodeQL doesn't distinguish between JavaScript and TypeScript
            'js/ts': ['js', 'ts', 'javascript', 'typescript'],
            'c#': ['csharp', 'cs'],
            'python': ['py'],
            'ruby': ['rb'],
            'go': [],
            'php': [],
            'scala': [],
            'rust': [],
            'swift': [],
            'vb.net': ['vbnet'],
            'lua': [],
            'r': [],
            'elixir': [],
            'ocaml': [],
            'html': [],
            'css': [],
            'xml': [],
            'yaml': [],
            'json': [],
            'bash': ['sh', 'shell'],
            'dockerfile': ['docker'],
            'terraform': ['hcl', 'cloudformation'],
        }
        new_languages = set()
        for language in languages:
            was_added = False
            for language_name, language_aliases in language_map.items():
                if language == language_name or language in language_aliases:
                    was_added = True
                    new_languages.add(language_name)
                    break
            if not was_added:
                new_languages.add('other')  # +'-'+self.data_source+'-'+language)
        return list(new_languages)

    @staticmethod
    def normalize_cwes(cwes: List[str]) -> List[str]:
        # remove trailing zeros after the dash
        return [re.sub(r'-(0+)(\d+)', r'-\2', cwe) for cwe in cwes]

    def convert(self, rule: RawSecurityRule, date: datetime) -> ComparableRule:
        cwes = self.normalize_cwes(self._upper_list(self.get_cwes(rule)))
        languages = self.normalize_languages(self._lower_list(self.get_languages(rule)))
        owasp_categories = []
        with contextlib.closing(OwaspCweMapper()) as mapper:
            owasp_categories = [mapper.fetch_short_mapping(cwe) for cwe in cwes]
        return ComparableRule(
            rule_id=rule.id,
            date=date,
            title=self.get_title(rule),
            description=self.get_description(rule),
            severity=self.get_severity(rule),
            cwes=cwes,
            owasp_categories=owasp_categories,
            languages=languages,
            data_source=self.data_source,
            is_generic=self.get_is_generic(rule))

    def get_title(self, rule: RawSecurityRule) -> str:
        raise NotImplementedError

    def get_description(self, rule: RawSecurityRule) -> str:
        raise NotImplementedError

    def get_severity(self, rule: RawSecurityRule) -> str:
        raise NotImplementedError

    def get_cwes(self, rule: RawSecurityRule) -> List[str]:
        raise NotImplementedError

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        raise NotImplementedError

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        raise NotImplementedError


class SonarQubeRuleConverter(RuleConverter):
    def __init__(self):
        super().__init__('sonarqube')

    def get_title(self, rule: RawSecurityRule) -> str:
        return rule.metadata['title']

    def get_description(self, rule: RawSecurityRule) -> str:
        return ''

    def get_severity(self, rule: RawSecurityRule) -> str:
        severity_map = {
            'Blocker': 'error',
            'Critical': 'error',
            'Major': 'warning',
            'Minor': 'info',
            'Info': 'info',
        }
        return severity_map[rule.metadata['defaultSeverity']]

    def get_cwes(self, rule: RawSecurityRule) -> List[str]:
        security_standards = rule.metadata.get('securityStandards', {})
        return [f'CWE-{cwe}' for cwe in security_standards.get('CWE', [])]

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        languages = [PurePath(rule.path).parent.parts[-1]]
        return languages

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        return False


class SemgrepRuleConverter(RuleConverter):
    def __init__(self):
        super().__init__('semgrep')

    def get_title(self, rule: RawSecurityRule) -> str:
        return rule.metadata['id']

    def get_description(self, rule: RawSecurityRule) -> str:
        return rule.metadata['message']

    def get_severity(self, rule: RawSecurityRule) -> str:
        severity_map = {
            'ERROR': 'error',
            'WARNING': 'warning',
            'INFO': 'info',
        }
        return severity_map[rule.metadata['severity']]

    def get_cwes(self, rule: RawSecurityRule) -> List[str]:
        raw_cwes = rule.metadata['metadata'].get('cwe', [])
        cwes = [raw_cwes] if isinstance(raw_cwes, str) else raw_cwes
        return [cwe.split(':')[0] for cwe in cwes]

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        return rule.metadata['languages']

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        return 'generic' in self.get_languages(rule)


class CodeQLRuleConverter(RuleConverter):
    def __init__(self):
        super().__init__('codeql')

    def get_title(self, rule: RawSecurityRule) -> str:
        return rule.metadata['name']

    def get_description(self, rule: RawSecurityRule) -> str:
        return rule.metadata['description']

    def get_severity(self, rule: RawSecurityRule) -> str:
        severity_map = {
            'error': 'error',
            'warning': 'warning',
            'recommendation': 'info',
        }
        if 'problem.severity' not in rule.metadata:
            logging.warning(f'No severity in {self.data_source} rule {rule.metadata["id"]}')
            return 'info'
        return severity_map[rule.metadata['problem.severity']]

    def get_cwes(self, rule: RawSecurityRule) -> List[str]:
        if 'tags' not in rule.metadata:
            logging.warning(f'No tags in {self.data_source} rule {rule.metadata["id"]}')
            return []
        return [tag.split('/')[2]
                for tag in rule.metadata.get('tags', '').split()
                if tag.startswith('external/cwe/')]

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        languages = [PurePath(rule.metadata['id']).parts[0]]
        return languages

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        return False


class JoernRuleConverter(RuleConverter):
    def __init__(self):
        super().__init__('joern')

    def get_title(self, rule: RawSecurityRule) -> str:
        return rule.metadata['title']

    def get_description(self, rule: RawSecurityRule) -> str:
        return rule.metadata['description']

    def get_severity(self, rule: RawSecurityRule) -> str:
        severity = int(float(rule.metadata['score']))
        if severity <= 3:
            return 'info'
        if severity <= 6:
            return 'warning'
        return 'error'

    def get_cwes(self, rule: RawSecurityRule) -> List[str]:
        return []

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        language = PurePath(rule.path).parent.parts[-1]
        return [language]

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        return False
