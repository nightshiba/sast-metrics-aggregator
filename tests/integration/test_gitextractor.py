import pytest

from gitextractor import *


def check_unique_ids(raw_rules: List[RawSecurityRule]):
    non_unique_rules = {}
    for raw_rule in raw_rules:
        if raw_rule.id in non_unique_rules:
            non_unique_rules[raw_rule.id].append(raw_rule)
        else:
            non_unique_rules[raw_rule.id] = [raw_rule]
    for rule_id, rules in non_unique_rules.items():
        if len(rules) > 1:
            print(f'Non-unique rule id: {rule_id}')
            for rule in rules:
                print(f'  {rule.path}')
    assert len(raw_rules) == len(set([rule.id for rule in raw_rules]))


def test_git_rules_repo_init():
    repo = GitSecurityRulesRepo('https://github.com/octocat/Spoon-Knife', ['*.html'])
    assert 'Spoon-Knife' in repo.cloned_repo_path
    assert 'Fork you' in repo.raw_rules[0].raw_data


def test_git_rules_repo_init_with_date():
    repo = GitSecurityRulesRepo('https://github.com/JareBear12418/Daily-Git-Commit', ['*.yaml'], datetime(2022, 2, 4))
    assert 'Daily-Git-Commit' in repo.cloned_repo_path
    assert 'February 03' in repo.raw_rules[0].raw_data
    print(repo.latest_commit)


def test_git_rules_repo_init_with_nonexistent_date():
    with pytest.raises(ValueError):
        GitSecurityRulesRepo('https://github.com/JareBear12418/Daily-Git-Commit', ['*.yaml'], datetime(2021, 2, 10))


def test_sonarqube_rules_repo_init():
    repo = SonarQubeRulesRepo()
    assert 'rspec' in repo.cloned_repo_path
    for raw_rule in repo.raw_rules:
        print(raw_rule.metadata)
        assert 'type' in raw_rule.metadata
        assert 'tags' in raw_rule.metadata
    check_unique_ids(repo.raw_rules)


def test_semgrep_rules_repo_init():
    repo = SemgrepRulesRepo()
    assert 'semgrep-rules' in repo.cloned_repo_path
    for raw_rule in repo.raw_rules:
        print(raw_rule.metadata)
        assert 'id' in raw_rule.metadata
        assert 'languages' in raw_rule.metadata
        assert 'metadata' in raw_rule.metadata
    check_unique_ids(repo.raw_rules)


def test_codeql_rules_repo_init():
    repo = CodeQLRulesRepo()
    assert 'codeql' in repo.cloned_repo_path
    for raw_rule in repo.raw_rules:
        print(raw_rule.metadata)
        assert 'name' in raw_rule.metadata
        assert 'id' in raw_rule.metadata
        assert 'description' in raw_rule.metadata
        assert 'kind' in raw_rule.metadata
    check_unique_ids(repo.raw_rules)


def test_joern_rules_repo_init():
    repo = JoernRulesRepo()
    assert 'joern' in repo.cloned_repo_path
    for raw_rule in repo.raw_rules:
        print(raw_rule.metadata)
        assert 'name' in raw_rule.metadata
        assert 'title' in raw_rule.metadata
        assert 'description' in raw_rule.metadata
        assert 'score' in raw_rule.metadata
        assert 'tags' in raw_rule.metadata
    check_unique_ids(repo.raw_rules)
