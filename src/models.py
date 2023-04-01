from typing import List

from sqlalchemy import Column, ForeignKey, Integer, String, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy.orm import relationship

Base = declarative_base()


class RuleCWE(Base):
    __tablename__ = 'rule_cwes'
    id = Column(Integer, primary_key=True)
    cwe = Column(String, nullable=False)
    rule_id: Mapped[str] = mapped_column(ForeignKey("comparable_rules.id"))

    def __init__(self, cwe: str):
        self.cwe = cwe

    def __repr__(self):
        return self.cwe

    def __lt__(self, other):
        return self.cwe < other.cwe


class RuleLanguage(Base):
    __tablename__ = 'rule_languages'
    id = Column(Integer, primary_key=True)
    language = Column(String, nullable=False)
    rule_id: Mapped[str] = mapped_column(ForeignKey("comparable_rules.id"))

    def __init__(self, language: str):
        self.language = language

    def __repr__(self):
        return self.language

    def __lt__(self, other):
        return self.language < other.language


class ComparableRule(Base):
    __tablename__ = 'comparable_rules'
    id: Mapped[str] = mapped_column(primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    cwe: Mapped[List[RuleCWE]] = relationship(backref="rule_cwe")
    languages: Mapped[List[RuleLanguage]] = relationship(backref="rule_language")
    data_source = Column(String, nullable=False)
    is_generic = Column(Boolean, nullable=False)

    def __init__(self, rule_id: str, name: str, description: str, severity: str, cwe: List[str], languages: List[str],
                 is_generic: bool, data_source: str):
        self.id = rule_id
        self.name = name
        self.description = description
        self.severity = severity  # error, warning, info
        self.cwe = list(map(RuleCWE, cwe))  # CWE-000
        self.languages = list(map(RuleLanguage, languages))
        self.is_generic = is_generic
        self.data_source = data_source

    def __repr__(self):
        return "<ComparableRule(rule_id='{}', name='{}', description='{}', severity={}, cwe={}, languages={}, " \
               "data_source={}, is_generic={})>" \
            .format(self.id, self.name, self.description, self.severity, self.cwe, self.languages, self.data_source,
                    self.is_generic)
