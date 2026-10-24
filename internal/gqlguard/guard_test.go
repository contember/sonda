package gqlguard

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// The fixtures are introspection results of the dev Contember engine (dev/seed-contember.sh):
// the reader role can only read, the writer role can write.
func loadFixture(t *testing.T, name string) *Schema {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	s, err := LoadIntrospection(data)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testRules() Rules {
	return Rules{
		Denied: func(entity, field string) bool {
			return field == "email" || (entity == "Article" && field == "secretNote")
		},
		MaxRows:   200,
		MaxDepth:  4,
		MaxFields: 50,
		MaxOffset: 1000,
	}
}

func TestSchemaModel(t *testing.T) {
	s := loadFixture(t, "contember_reader.json")
	if got := s.EntityNames(); !slices.Equal(got, []string{"Article", "Author", "Tag"}) {
		t.Fatalf("entities = %v", got)
	}
	if w := s.WriteFields(); len(w) != 0 {
		t.Fatalf("reader write fields = %v", w)
	}
	author := s.entities["Author"]
	if author.derived["paginateArticles"] != "articles" || author.derived["articlesBy"] != "articles" {
		t.Fatalf("derived = %v", author.derived)
	}
	if r := author.relations["articles"]; r.target != "Article" || !r.many {
		t.Fatalf("articles relation = %+v", r)
	}
	if !slices.Equal(author.unique, []string{"id", "email", "articles"}) {
		t.Fatalf("unique = %v", author.unique)
	}

	writer := loadFixture(t, "contember_writer.json")
	w := writer.WriteFields()
	if !slices.Contains(w, "Mutation.createArticle") || !slices.Contains(w, "Query.validateCreateArticle") {
		t.Fatalf("writer write fields = %v", w)
	}
}

func TestVisible(t *testing.T) {
	s := loadFixture(t, "contember_reader.json")
	rules := testRules()
	rules.Entities = []string{"Article", "Author"}
	entities, enums := s.Visible(rules)
	if len(entities) != 2 {
		t.Fatalf("entities = %+v", entities)
	}
	var article Entity
	for _, e := range entities {
		if e.Name == "Article" {
			article = e
		}
		for _, f := range e.Fields {
			if f.Name == "email" || f.Name == "secretNote" || f.Name == "tags" {
				t.Errorf("%s.%s should be hidden", e.Name, f.Name)
			}
		}
	}
	if len(article.Fields) == 0 || !slices.Equal(enums["ArticleStatus"], []string{"draft", "published"}) {
		t.Fatalf("article = %+v, enums = %v", article, enums)
	}
}

func TestVisibleUniqueSkipsHiddenTargets(t *testing.T) {
	s := loadFixture(t, "contember_reader.json")
	rules := testRules()
	rules.Entities = []string{"Author"}
	entities, _ := s.Visible(rules)
	if len(entities) != 1 || slices.Contains(entities[0].Unique, "articles") || !slices.Contains(entities[0].Unique, "id") {
		t.Fatalf("entities = %+v", entities)
	}
}

func TestCheckAccepts(t *testing.T) {
	s := loadFixture(t, "contember_reader.json")
	cases := []struct {
		name, query, vars, want string
		rows                    int
	}{
		{
			name:  "list with limit",
			query: `{ listArticle(limit: 10) { id title } }`,
			want:  `query { listArticle(limit: 10) { id title } }`,
			rows:  10,
		},
		{
			name:  "get by unique",
			query: `query Q { getAuthor(by: {id: "8c0f3a4e-0000-0000-0000-000000000000"}) { name articles(limit: 5) { title } } }`,
			want:  `query { getAuthor(by: {id: "8c0f3a4e-0000-0000-0000-000000000000"}) { name articles(limit: 5) { title } } }`,
			rows:  5,
		},
		{
			name:  "paginate count",
			query: `{ paginateArticle(first: 1, filter: {status: {eq: published}}) { pageInfo { totalCount } } }`,
			want:  `query { paginateArticle(first: 1, filter: {status: {eq: published}}) { pageInfo { totalCount } } }`,
			rows:  1,
		},
		{
			name:  "nested rows multiply",
			query: `{ listAuthor(limit: 10) { articles(limit: 5) { tags(limit: 2) { name } } } }`,
			rows:  10 + 50 + 100,
		},
		{
			name:  "fragments and aliases are inlined",
			query: `query { a: listArticle(limit: 2) { ...F } } fragment F on Article { title author { name } ... on Article { id } }`,
			want:  `query { a: listArticle(limit: 2) { title author { name } id } }`,
			rows:  2,
		},
		{
			name:  "variables are inlined",
			query: `query($n: Int!, $f: ArticleWhere, $o: [ArticleOrderBy!]) { listArticle(limit: $n, filter: $f, orderBy: $o) { title } }`,
			vars:  `{"n": 3, "f": {"title": {"contains": "Go \"x\""}, "status": {"eq": "published"}}, "o": {"title": "asc"}}`,
			want:  `query { listArticle(limit: 3, filter: {status: {eq: published}, title: {contains: "Go \"x\""}}, orderBy: [{title: asc}]) { title } }`,
			rows:  3,
		},
		{
			name:  "missing nullable variable drops the argument",
			query: `query($f: ArticleWhere) { listArticle(limit: 1, filter: $f) { id } }`,
			want:  `query { listArticle(limit: 1) { id } }`,
			rows:  1,
		},
		{
			name:  "variable default is used",
			query: `query($n: Int = 7) { listTag(limit: $n) { name } }`,
			want:  `query { listTag(limit: 7) { name } }`,
			rows:  7,
		},
		{
			name:  "filter through relations and operators",
			query: `{ listArticle(limit: 5, filter: {or: [{author: {name: {eq: "A"}}}, {not: {tags: {name: {eq: "go"}}}}]}) { id } }`,
			rows:  5,
		},
		{
			name:  "derived reducer and paginate relation",
			query: `{ getAuthor(by: {id: "x"}) { articlesBy(by: {id: "y"}) { title } paginateArticles(first: 3) { edges { node { title } } } } }`,
			rows:  3,
		},
		{
			name:  "has-one relations add no rows",
			query: `{ listArticle(limit: 200) { author { name } } }`,
			rows:  200,
		},
		{
			name:  "typename and offset",
			query: `{ __typename listTag(limit: 2, offset: 10) { __typename name } }`,
			rows:  2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Check(s, tc.query, []byte(tc.vars), testRules())
			if err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if tc.want != "" && res.Query != tc.want {
				t.Errorf("query\n got %s\nwant %s", res.Query, tc.want)
			}
			if res.Rows != tc.rows {
				t.Errorf("rows = %d, want %d", res.Rows, tc.rows)
			}
		})
	}
}

func TestCheckRejects(t *testing.T) {
	s := loadFixture(t, "contember_reader.json")
	cases := []struct {
		name, query, vars, want string
	}{
		{"syntax", `{ listArticle(limit: 1) { id }`, "", "invalid GraphQL"},
		{"unknown field", `{ listArticle(limit: 1) { nope } }`, "", "invalid GraphQL"},
		{"mutation", `mutation { createArticle { ok } }`, "", "invalid GraphQL"},
		{"two operations", `query A { listTag(limit: 1) { id } } query B { listTag(limit: 1) { id } }`, "", "exactly one operation"},
		{"introspection schema", `{ __schema { types { name } } }`, "", "introspection"},
		{"introspection type", `{ __type(name: "Article") { name } }`, "", "introspection"},
		{"schema root field", `{ schema { enums { name } } }`, "", "root field schema is not allowed"},
		{"transaction", `{ transaction { listArticle(limit: 1) { id } } }`, "", "root field transaction is not allowed"},
		{"info", `{ _info { description } }`, "", "root field _info is not allowed"},
		{"meta", `{ listArticle(limit: 1) { _meta { title { readable } } } }`, "", "Article._meta is not supported"},
		{"list without limit", `{ listArticle { id } }`, "", "listArticle needs limit"},
		{"has-many without limit", `{ listAuthor(limit: 1) { articles { id } } }`, "", "articles needs limit"},
		{"paginate without first", `{ paginateArticle { pageInfo { totalCount } } }`, "", "needs first"},
		{"limit over max", `{ listArticle(limit: 201) { id } }`, "", "limit is 200"},
		{"rows multiply over max", `{ listAuthor(limit: 20) { articles(limit: 20) { id } } }`, "", "limit is 200"},
		{"aliases multiply rows", `{ a: listTag(limit: 150) { id } b: listTag(limit: 150) { id } }`, "", "limit is 200"},
		{"null limit variable", `query($n: Int) { listArticle(limit: $n) { id } }`, "", "needs limit"},
		{"explicit null limit", `{ listArticle(limit: null) { id } }`, "", "must be an integer"},
		{"negative limit", `{ listArticle(limit: -1) { id } }`, "", "non-negative"},
		{"offset over max", `{ listArticle(limit: 1, offset: 5000) { id } }`, "", "maximum is 1000"},
		{"depth", `{ listAuthor(limit: 1) { articles(limit: 1) { author { articles(limit: 1) { author { name } } } } } }`, "", "more than 4 entity levels"},
		{"denied column", `{ listAuthor(limit: 1) { email } }`, "", "Author.email is not allowed"},
		{"denied column via fragment", `{ listArticle(limit: 1) { ...F } } fragment F on Article { secretNote }`, "", "secretNote is not allowed"},
		{"denied field in filter", `{ listAuthor(limit: 1, filter: {email: {eq: "a@b.c"}}) { id } }`, "", "Author.email is not allowed in filter"},
		{"denied field in nested filter", `{ listArticle(limit: 1, filter: {and: [{author: {email: {contains: "@"}}}]}) { id } }`, "", "Author.email is not allowed in filter"},
		{"denied field in filter variable", `query($f: AuthorWhere) { listAuthor(limit: 1, filter: $f) { id } }`, `{"f": {"not": {"email": {"eq": "x"}}}}`, "Author.email is not allowed in filter"},
		{"denied field in by", `{ getAuthor(by: {email: "a@b.c"}) { id } }`, "", "Author.email is not allowed in by"},
		{"denied field in orderBy", `{ listArticle(limit: 1, orderBy: [{author: {email: asc}}]) { id } }`, "", "Author.email is not allowed in orderBy"},
		{"denied field in has-one filter", `{ listArticle(limit: 1) { author(filter: {email: {eq: "x"}}) { id } } }`, "", "Author.email is not allowed in filter"},
		{"denied field in totalCount filter", `{ paginateArticle(first: 1, filter: {secretNote: {isNull: false}}) { pageInfo { totalCount } } }`, "", "secretNote is not allowed"},
		{"directive", `{ listArticle(limit: 1) { id @skip(if: true) } }`, "", "directives are not allowed"},
		{"include directive", `query($x: Boolean!) { listArticle(limit: 1) @include(if: $x) { id } }`, `{"x": true}`, "directives are not allowed"},
		{"undefined variable", `{ listArticle(limit: 1) { id } }`, `{"n": 1}`, "not defined"},
		{"bad variable type", `query($n: Int!) { listArticle(limit: $n) { id } }`, `{"n": "x"}`, "invalid GraphQL"},
		{"variables not object", `{ listArticle(limit: 1) { id } }`, `[1]`, "JSON object"},
		{"too many fields", `{ listArticle(limit: 1) { ` + strings.Repeat("id ", 60) + `} }`, "", "more than 50 fields"},
		{"fragment explosion", `{ listArticle(limit: 1) { ...A } } fragment A on Article { ...B ...B } fragment B on Article { ...C ...C } fragment C on Article { ...D ...D } fragment D on Article { ...E ...E } fragment E on Article { ...G ...G } fragment G on Article { id title }`, "", "more than 50 fields"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Check(s, tc.query, []byte(tc.vars), testRules())
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// A large flat query is rejected before validation, whose overlapping-fields step is
// quadratic in the number of fields.
func TestCheckRejectsLargeQueryQuickly(t *testing.T) {
	s := loadFixture(t, "contember_reader.json")
	query := `{ listArticle(limit: 1) { ` + strings.Repeat("id ", 5000) + `} }`
	start := time.Now()
	_, err := Check(s, query, nil, testRules())
	if err == nil || !strings.Contains(err.Error(), "more than 50 fields") {
		t.Fatalf("err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("rejection took %s", elapsed)
	}
}

func TestCheckAllowList(t *testing.T) {
	s := loadFixture(t, "contember_reader.json")
	rules := testRules()
	rules.Entities = []string{"Article", "Author"}
	for _, q := range []string{
		`{ listTag(limit: 1) { id } }`,
		`{ listArticle(limit: 1) { tags(limit: 1) { id } } }`,
		`{ listArticle(limit: 1) { paginateTags(first: 1) { pageInfo { totalCount } } } }`,
		`{ listArticle(limit: 1, filter: {tags: {name: {eq: "go"}}}) { id } }`,
	} {
		if _, err := Check(s, q, nil, rules); err == nil || !strings.Contains(err.Error(), "entity Tag is not allowed") {
			t.Errorf("%s: err = %v", q, err)
		}
	}
	if _, err := Check(s, `{ listArticle(limit: 1) { author { name } } }`, nil, rules); err != nil {
		t.Errorf("allowed relation rejected: %v", err)
	}
}

func TestDeniedRelationBlocksDerivedFields(t *testing.T) {
	s := loadFixture(t, "contember_reader.json")
	rules := testRules()
	rules.Denied = func(entity, field string) bool { return entity == "Author" && field == "articles" }
	for _, q := range []string{
		`{ getAuthor(by: {id: "x"}) { articles(limit: 1) { id } } }`,
		`{ getAuthor(by: {id: "x"}) { paginateArticles(first: 1) { pageInfo { totalCount } } } }`,
		`{ getAuthor(by: {id: "x"}) { articlesBy(by: {id: "y"}) { id } } }`,
		`{ listAuthor(limit: 1, filter: {articles: {title: {eq: "x"}}}) { id } }`,
		`{ getAuthor(by: {articles: {id: "y"}}) { id } }`,
	} {
		if _, err := Check(s, q, nil, rules); err == nil || !strings.Contains(err.Error(), "Author.articles is not allowed") {
			t.Errorf("%s: err = %v", q, err)
		}
	}
}

// FuzzCheck checks that every accepted query re-validates and is stable under normalization.
func FuzzCheck(f *testing.F) {
	for _, seed := range []string{
		`{ listArticle(limit: 1) { id } }`,
		`query { a: listTag(limit: 2) { ...F } } fragment F on Tag { name }`,
		`{ paginateArticle(first: 1) { pageInfo { totalCount } edges { node { title } } } }`,
	} {
		f.Add(seed)
	}
	data, err := os.ReadFile("testdata/contember_reader.json")
	if err != nil {
		f.Fatal(err)
	}
	s, err := LoadIntrospection(data)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, query string) {
		res, err := Check(s, query, nil, testRules())
		if err != nil {
			return
		}
		again, err := Check(s, res.Query, nil, testRules())
		if err != nil {
			t.Fatalf("normalized query rejected: %v\n%s", err, res.Query)
		}
		if again.Query != res.Query || again.Rows != res.Rows {
			t.Fatalf("normalization not stable:\n%s\n%s", res.Query, again.Query)
		}
	})
}
