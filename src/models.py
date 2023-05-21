from datetime import datetime
from typing import List

from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import mapped_column, Mapped
from sqlalchemy.orm import relationship

Base = declarative_base()


class RuleCWE(Base):
    __tablename__ = 'rule_cwes'
    id = Column(Integer, primary_key=True)
    cwe = Column(String, nullable=False)
    owasp_category = Column(String, nullable=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("comparable_rules.id"))

    def __init__(self, cwe: str, owasp_category: str | None):
        self.cwe = cwe  # CWE-12
        self.owasp_category = owasp_category  # A01:2021

    def __repr__(self):
        return self.cwe + ' - ' + self.owasp_category

    def __lt__(self, other):
        if self.cwe < other.cwe:
            return True
        elif self.cwe == other.cwe:
            return self.owasp_category < other.owasp_category
        return False


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
    id: Mapped[str] = mapped_column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    date = Column(DateTime, nullable=False)  # date for which the rule was fetched
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    cwes: Mapped[List[RuleCWE]] = relationship(backref="rule_cwe")
    languages: Mapped[List[RuleLanguage]] = relationship(backref="rule_language")
    data_source = Column(String, nullable=False)
    is_generic = Column(Boolean, nullable=False)

    def __init__(self, rule_id: str, date: datetime, title: str, description: str, severity: str, languages: List[str],
                 cwes: List[str], owasp_categories: List[str | None], is_generic: bool, data_source: str):
        self.name = rule_id
        self.date = date
        self.title = title
        self.description = description
        self.severity = severity  # error, warning, info
        self.cwes = list(map(RuleCWE, cwes, owasp_categories))
        self.languages = list(map(RuleLanguage, languages))
        self.is_generic = is_generic
        self.data_source = data_source

    def __repr__(self):
        return "<ComparableRule(rule_id='{}', name='{}', description='{}', severity={}, cwes={}, languages={}, " \
               "data_source={}, is_generic={})>" \
            .format(self.id, self.name, self.description, self.severity, self.cwes, self.languages, self.data_source,
                    self.is_generic)
