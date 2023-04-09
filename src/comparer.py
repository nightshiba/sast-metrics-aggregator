from collections import Counter
from datetime import datetime
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


def print_corpus_stats(corpus):
    unique_languages = set()
    rules_by_language_counter = Counter()
    for rule in corpus:
        languages = list(map(lambda m: m.language, rule.languages))
        unique_languages.update(languages)
        rules_by_language_counter.update(languages)

    print(sorted(unique_languages))
    print(rules_by_language_counter)


def main():
    s = Session()

    time_dates_to_process = [
        datetime(2021, 7, 2),
        datetime(2021, 11, 13),
        datetime(2022, 4, 5),
        datetime(2022, 10, 18),
        datetime(2023, 4, 4)
    ]
    sonarqube_available_rules_path = PurePath('misc/community_edition_rule_keys.json')

    rule_equalizer = RuleEqualizer()
    for date in time_dates_to_process:
        corpus = []
        print(f'\nProcessing date {date}')
        sonarqube_available_rules = get_rules_for_release_date(sonarqube_available_rules_path, date)
        if not sonarqube_available_rules:
            print('Skipping current date because no SonarQube rules were found')
            continue
        repos = [
            SonarQubeRulesRepo(date, sonarqube_available_rules),
            SemgrepRulesRepo(date),
            CodeQLRulesRepo(date),
            JoernRulesRepo(date)
        ]
        for repo in repos:
            print(f'Converting repo {repo.__class__.__name__} at commit {repo.latest_commit[:8]}')
            current_repo_rules = rule_equalizer.convert(repo)
            corpus.extend(current_repo_rules)
            s.add_all(current_repo_rules)
        print_corpus_stats(corpus)

    s.commit()
    s.close()


if __name__ == '__main__':
    init_db()
    main()
