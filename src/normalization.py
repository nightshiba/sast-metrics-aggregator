import logging
from pathlib import PurePath
from typing import List

from gitextractor import RawSecurityRule, GitSecurityRulesRepo, SonarQubeRulesRepo, SemgrepRulesRepo, CodeQLRulesRepo, \
    JoernRulesRepo
from models import ComparableRule


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
        return list(map(rule_converter.convert, rules_repo.raw_rules))


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
            'c': ['cfamily'],
            'c++': ['cpp', 'cfamily'],
            'c#': ['csharp'],
            'java': [],
            'javascript': ['js'],
            'typescript': ['ts'],
            'python': ['py'],
            'ruby': ['rb'],
            'go': [],
            'php': [],
            'kotlin': ['kt'],
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
            'terraform': ['hcl']
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

    def convert(self, rule: RawSecurityRule) -> ComparableRule:
        cwe = self._upper_list(self.get_cwe(rule))
        languages = self.normalize_languages(self._lower_list(self.get_languages(rule)))
        return ComparableRule(
            rule_id=rule.id,
            name=self.get_name(rule),
            description=self.get_description(rule),
            severity=self.get_severity(rule),
            cwe=cwe,
            languages=languages,
            data_source=self.data_source,
            is_generic=self.get_is_generic(rule))

    def get_name(self, rule: RawSecurityRule) -> str:
        raise NotImplementedError

    def get_description(self, rule: RawSecurityRule) -> str:
        raise NotImplementedError

    def get_severity(self, rule: RawSecurityRule) -> str:
        raise NotImplementedError

    def get_cwe(self, rule: RawSecurityRule) -> List[str]:
        raise NotImplementedError

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        raise NotImplementedError

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        raise NotImplementedError


class SonarQubeRuleConverter(RuleConverter):
    def __init__(self):
        super().__init__('sonarqube')

    def get_name(self, rule: RawSecurityRule) -> str:
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

    def get_cwe(self, rule: RawSecurityRule) -> List[str]:
        security_standards = rule.metadata.get('securityStandards', {})
        return [f'CWE-{cwe}' for cwe in security_standards.get('CWE', [])]

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        languages = [PurePath(rule.path).parent.parts[-1]]
        if 'javascript' in languages:
            languages.append('typescript')
        return languages

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        return False


class SemgrepRuleConverter(RuleConverter):
    def __init__(self):
        super().__init__('semgrep')

    def get_name(self, rule: RawSecurityRule) -> str:
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

    def get_cwe(self, rule: RawSecurityRule) -> List[str]:
        cwes = []
        if 'cwe' in rule.metadata:
            raw_cwe = rule.metadata['cwe']
            cwes = [raw_cwe] if isinstance(raw_cwe, str) else raw_cwe
        return [cwe.split(':')[0] for cwe in cwes]

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        return rule.metadata['languages']

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        return 'generic' in self.get_languages(rule)


class CodeQLRuleConverter(RuleConverter):
    def __init__(self):
        super().__init__('codeql')

    def get_name(self, rule: RawSecurityRule) -> str:
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

    def get_cwe(self, rule: RawSecurityRule) -> List[str]:
        if 'tags' not in rule.metadata:
            logging.warning(f'No tags in {self.data_source} rule {rule.metadata["id"]}')
            return []
        return [tag.split('/')[2]
                for tag in rule.metadata.get('tags', '').split()
                if tag.startswith('external/cwe/')]

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        languages = [PurePath(rule.metadata['id']).parts[0]]
        if 'js' in languages:
            languages.append('ts')
        return languages

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        return False


class JoernRuleConverter(RuleConverter):
    def __init__(self):
        super().__init__('joern')

    def get_name(self, rule: RawSecurityRule) -> str:
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

    def get_cwe(self, rule: RawSecurityRule) -> List[str]:
        return []

    def get_languages(self, rule: RawSecurityRule) -> List[str]:
        language = PurePath(rule.path).parent.parts[-1]
        if language == 'android':
            languages = ['java', 'kotlin']
        else:
            languages = [language]
        return languages

    def get_is_generic(self, rule: RawSecurityRule) -> bool:
        return False
