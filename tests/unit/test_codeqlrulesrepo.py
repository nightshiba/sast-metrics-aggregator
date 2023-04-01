import unittest

from gitextractor import CodeQLRulesRepo
from unit.helpers import read_resource


class CodeQLRulesRepoTestCase(unittest.TestCase):
    def setUp(self):
        self.example_query = read_resource("codeql/example_query.ql")

    def test_load_ql(self):
        loaded_query = CodeQLRulesRepo.load_ql(self.example_query)
        self.assertEqual(['name', 'description', 'kind', 'problem.severity', 'security-severity',
                          'sub-severity', 'precision', 'id', 'tags'], list(loaded_query.keys()))

        self.assertEqual('Some name', loaded_query['name'])
        self.assertEqual('Multiple lines of description. This is the second line.', loaded_query['description'])
        self.assertEqual('some-kind', loaded_query['kind'])
        self.assertEqual('error', loaded_query['problem.severity'])
        self.assertEqual('9.9', loaded_query['security-severity'])
        self.assertEqual('high', loaded_query['sub-severity'])
        self.assertEqual('high', loaded_query['precision'])
        self.assertEqual('py/some-name', loaded_query['id'])
        self.assertEqual('some-tag security external/cwe/cwe-123 external/cwe/cwe-321', loaded_query['tags'])


if __name__ == '__main__':
    unittest.main()
