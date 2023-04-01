from collections import Counter
from pathlib import PurePath

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import config
from gitextractor import SonarQubeRulesRepo, SemgrepRulesRepo, CodeQLRulesRepo, JoernRulesRepo
from misc.extract_sonarqube_available_rules import get_rules_for_release_date
from models import Base
from normalization import RuleEqualizer

engine = create_engine(config.DATABASE_URI)
Session = sessionmaker(bind=engine)


def init_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)


def main():
    s = Session()

    time_dates_to_process = ['2022-12-19', '2023-03-16']
    commit_hashes_per_repo_to_process = []
    sonarqube_available_rules_path = PurePath('misc/community_edition_rule_keys.json')
    sonarqube_available_rules = get_rules_for_release_date(sonarqube_available_rules_path, time_dates_to_process[1])
    # TODO get sonarqube rules for the given time dates
    # TODO init repos for each commit hashes (and available rules for sonarqube)
    repos = [SonarQubeRulesRepo(sonarqube_available_rules), SemgrepRulesRepo(), CodeQLRulesRepo(), JoernRulesRepo()]
    rule_equalizer = RuleEqualizer()
    corpus = []
    for repo in repos:
        print('Processing repo: {}'.format(repo.__class__.__name__))
        rules = rule_equalizer.convert(repo)
        corpus.extend(rules)
        s.add_all(rules)

    unique_languages = set()
    rules_by_language_counter = Counter()
    for rule in corpus:
        languages = list(map(lambda m: m.language, rule.languages))
        unique_languages.update(languages)
        rules_by_language_counter.update(languages)

    print(sorted(unique_languages))
    print(rules_by_language_counter)

    s.commit()
    s.close()


if __name__ == '__main__':
    init_db()
    main()

# Counter({'other': 517, 'python': 422, 'javascript': 403, 'java': 379, 'terraform': 301, 'typescript': 197, 'ruby': 164, 'php': 158, 'c#': 133, 'go': 126, 'c++': 98, 'c': 87, 'kotlin': 71, 'swift': 61, 'vb.net': 59, 'scala': 54, 'rust': 38, 'xml': 38, 'html': 34, 'dockerfile': 26, 'css': 21, 'json': 5, 'bash': 4, 'yaml': 4})
