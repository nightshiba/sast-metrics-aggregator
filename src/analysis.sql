-- Rules with supported languages
SELECT r.id, r.name, r.description, r.severity, r.data_source, r.is_generic, l.language, r.date from comparable_rules as r join rule_languages as l on r.id = l.rule_id where r.date='2023-04-04'
-- Rules with CWEs
SELECT r.id, r.name, r.description, r.severity, r.data_source, r.is_generic, c.cwe, c.owasp_category from comparable_rules as r join rule_cwes as c on r.id = c.rule_id where r.date='2023-04-04'
-- Rules quantity per language
SELECT "source"."language" AS "language", COUNT(*) AS "count", "source"."data_source" AS "data_source"
FROM (SELECT r.id, r.name, r.description, r.severity, r.data_source, r.is_generic, l.language from comparable_rules as r join rule_languages as l on r.id = l.rule_id where r.date='2023-04-04' ) AS "source"
GROUP BY "source"."language", "source"."data_source"
ORDER BY "source"."language" ASC
-- Rules quantity per CWE
SELECT "source"."owasp_category" AS "owasp_category", "source"."data_source" AS "data_source", COUNT(*) AS "count"
FROM (SELECT r.id, r.name, r.description, r.severity, r.data_source, r.is_generic, c.cwe, c.owasp_category from comparable_rules as r join rule_cwes as c on r.id = c.rule_id where r.date='2023-04-04' ) AS "source"
GROUP BY "source"."owasp_category", "source"."data_source"
ORDER BY "source"."owasp_category" ASC, "source"."data_source" ASC
-- Rules updates per language
SELECT r.data_source, r.date, COUNT(*) AS "count" from comparable_rules as r join rule_languages as l on r.id = l.rule_id WHERE l.language = 'python'
GROUP BY r.data_source, r.date
ORDER BY r.date ASC
-- Rules updates per CWE
SELECT "source"."owasp_category" AS "owasp_category", "source"."data_source" AS "data_source", "source"."date", COUNT(*) AS "count"
FROM (SELECT r.id, r.name, r.description, r.severity, r.data_source, r.is_generic, c.cwe, c.owasp_category, r.date from comparable_rules as r join rule_cwes as c on r.id = c.rule_id) AS "source"
GROUP BY "source"."owasp_category", "source"."data_source", "source"."date"
ORDER BY "source"."owasp_category" ASC, "source"."data_source", "source"."date" ASC
