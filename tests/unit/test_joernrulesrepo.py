import unittest

from gitextractor import JoernRulesRepo
from unit.helpers import read_resource


class JoernRulesRepoTestCase(unittest.TestCase):
    def setUp(self):
        self.example_queries = read_resource("joern/example_queries.scala")

    def test_load_scala(self):
        loaded_queries = JoernRulesRepo.load_scala(self.example_queries)
        self.assertEqual(3, len(loaded_queries))
        for query in loaded_queries:
            self.assertEqual(['name', 'title', 'description', 'score', 'tags'], list(query.keys()))

        self.assertEqual('some-query-name', loaded_queries[0]['name'])

        self.assertEqual('Some text.', loaded_queries[0]['description'])
        self.assertEqual('Some text. Big Text.', loaded_queries[1]['description'])
        self.assertEqual('-', loaded_queries[2]['description'])

        self.assertEqual('Title', loaded_queries[0]['title'])

        self.assertEqual('5', loaded_queries[0]['score'])

        self.assertEqual('android', loaded_queries[0]['tags'])
        self.assertEqual('tag1, tag2', loaded_queries[1]['tags'])


if __name__ == '__main__':
    unittest.main()
