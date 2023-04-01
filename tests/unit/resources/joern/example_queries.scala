package ...

import ...

object SomeQueryBundle extends QueryBundle {

  @q
  def some_query(): Query =
    Query.make(
      name = "some-query-name",
      author = Crew.someauthor,
      title = "Title",
      description = """
          |Some text.
          |""".stripMargin,
      score = 5,
      withStrRep({
      ...
      }),
      tags = List(QueryTags.android)
    )


  @q
  def some_query(): Query =
    Query.make(
      name = "some-name",
      author = Crew.someauthor,
      title = "Title",
      description = """
          |Some text.
          |Big
          |Text.""".stripMargin,
      score = 9,
      withStrRep({
      ...
      }),
      tags = List(QueryTags.tag1, QueryTags.tag2),
      something = a
    )

  @q
  def some_query()(foo: bar): Query =
    Query.make(
      name = "some_name",
      author = Crew.someauthor,
      title = "Title",
      description = "-",
      score = 1,
      withStrRep({
      ...
      }),
      tags = List(QueryTags.some, QueryTags.tags)
    )
}
