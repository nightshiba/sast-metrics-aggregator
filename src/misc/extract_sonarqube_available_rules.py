import argparse
import getpass
import json
import logging
import sys
from datetime import datetime
from pathlib import PurePath
from typing import TypedDict, List, Any

import requests

DEFAULT_AVAILABLE_RULES_PATH = 'available_rules.json'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
s = requests.Session()


class AvailableRules(TypedDict):
    rule_key: str
    rule_data: dict[str, List[Any]]
    # html_description: str


AvailableRuleKeys = List[str]


def get_rules_for_release_date(available_rules_path: PurePath, release_date: datetime) -> AvailableRuleKeys:
    with open(available_rules_path, 'r') as f:
        available_rules = json.load(f)
    release_date_str = release_date.strftime('%Y-%m-%d')
    available_rule_keys = []
    for rule_key, rule_data in available_rules.items():
        if release_date_str in rule_data['presented_in_release_date']:
            rspec_rule_key = f'{rule_data["rspec_language"]}:{rule_key.split(":")[1]}'
            available_rule_keys.append(rspec_rule_key)
    return available_rule_keys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--api-url', required=True, help='SonarQube API URL')
    parser.add_argument('--release-date', required=True, help='SonarQube release date')
    parser.add_argument('--existing-available-rules-path', required=False,
                        help='Path to a JSON file containing existing extracted rules for other release dates')
    args = parser.parse_args()

    user = input('SonarQube API user: ')
    password = getpass.getpass('SonarQube API password: ')
    response = s.post(args.api_url + 'api/authentication/login', data={'login': user, 'password': password})
    if response.status_code != 200:
        logger.error('Could not authenticate to SonarQube API')
        sys.exit(1)
    print('Successfully authenticated to SonarQube API')

    if not args.api_url.endswith('/'):
        args.api_url += '/'

    if args.existing_available_rules_path:
        existing_available_rules = load_available_rules(args.existing_available_rules_path)
    else:
        existing_available_rules = {}

    fetched_release_available_rules = extract_available_rules_for_release_date(args.api_url, args.release_date)
    merged_available_rules = merge_available_rules(existing_available_rules, fetched_release_available_rules)
    save_available_rules(merged_available_rules)


def load_available_rules(available_rules_path: str) -> AvailableRules:
    with open(available_rules_path, 'r') as f:
        available_rules = json.load(f)
    return available_rules


def rspec_language_mapper(language: str, rule_key: str) -> str:
    valid_rspec_languages = ['abap', 'apex', 'cfamily', 'cobol', 'csharp', 'css', 'docker', 'flex', 'go', 'html', 'java', 'javascript', 'kotlin', 'php', 'pli', 'plsql', 'python', 'rpg', 'ruby', 'rust', 'scala', 'secrets', 'solidity', 'swift', 'text', 'tsql', 'vb6', 'vbnet', 'cloudformation', 'terraform', 'kubernetes', 'xml']

    # map language to rspec language
    if language == 'c#':
        language = 'csharp'
    elif language == 'vb.net':
        language = 'vbnet'
    elif language == 'typescript':
        language = 'javascript'

    if language in valid_rspec_languages:
        return language
    logging.warning(f'There is no rspec for language {language} (rule key {rule_key}), skipping')


def extract_available_rules_for_release_date(api_url: str, release_date: str) -> AvailableRules:
    available_rules = {}
    page = 1
    while True:
        response = s.get(api_url + 'api/rules/search', params={'p': page, 'ps': 500})
        if response.status_code != 200:
            logger.error(f'Failed to fetch rules from SonarQube API: {response.text}')
            sys.exit(1)
        response_json = response.json()
        for rule in response_json['rules']:
            rspec_language = rspec_language_mapper(rule['langName'].lower(), rule['key'])
            if rspec_language is None:
                continue
            available_rules[rule['key']] = {
                'presented_in_release_date': [release_date],
                'rspec_language': rspec_language,
                # 'html_description': rule['htmlDesc'],
            }
        if response_json['total'] <= page * 500:
            break
        page += 1
    return available_rules


def merge_available_rules(existing_available_rules: AvailableRules,
                          fetched_release_available_rules: AvailableRules) -> AvailableRules:
    for rule_key, rule in fetched_release_available_rules.items():
        if rule_key in existing_available_rules:
            existing_available_rules[rule_key]['presented_in_release_date'].append(rule['presented_in_release_date'][0])
            existing_available_rules[rule_key]['rspec_language'] = rule['rspec_language']
        else:
            existing_available_rules[rule_key] = rule
        existing_available_rules[rule_key]['presented_in_release_date'] = sorted(
            list(set(existing_available_rules[rule_key]['presented_in_release_date'])))
    return existing_available_rules


def save_available_rules(available_rules: AvailableRules):
    with open(DEFAULT_AVAILABLE_RULES_PATH, 'w') as f:
        json.dump(available_rules, f, indent=4)


if __name__ == '__main__':
    main()
