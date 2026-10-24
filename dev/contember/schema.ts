// Contember schema for the sonda_test dev project (see dev/seed-contember.sh).
//
// The seed script does not run this file; it POSTs the generated dev/contember/migrate.json.
// After changing the model or ACL, regenerate the migration with a project reset
// (docker compose -f dev/docker-compose.yml down -v contember contember-postgres):
//
//   cd "$(mktemp -d)" && bun init -y >/dev/null && \
//     bun add @contember/schema-definition@2.0.8 @contember/schema-migrations@2.0.8 @contember/schema-utils@2.0.8 && \
//     printf '{"compilerOptions":{"experimentalDecorators":true}}' > tsconfig.json && \
//     cp <sonda>/dev/contember/schema.ts . && bun schema.ts > <sonda>/dev/contember/migrate.json
//
// Keep the package versions equal to the contember/engine image tag in dev/docker-compose.yml.
import { c, createSchema } from '@contember/schema-definition'
import { SchemaDiffer, SchemaMigrator, ModificationHandlerFactory, VERSION_LATEST } from '@contember/schema-migrations'
import { emptySchema } from '@contember/schema-utils'

export const ArticleStatus = c.createEnum('draft', 'published')

export class Author {
	name = c.stringColumn().notNull()
	email = c.stringColumn().notNull().unique()
	articles = c.oneHasMany(Article, 'author')
}

export class Article {
	title = c.stringColumn().notNull()
	published = c.boolColumn().notNull().default(false)
	status = c.enumColumn(ArticleStatus).notNull().default('draft')
	author = c.manyHasOne(Author, 'articles').setNullOnDelete()
	tags = c.manyHasMany(Tag, 'articles')
	secretNote = c.stringColumn()
}

export class Tag {
	name = c.stringColumn().notNull().unique()
	articles = c.manyHasManyInverse(Article, 'tags')
}

const schema = createSchema({ ArticleStatus, Author, Article, Tag }, schema => {
	const entities = Object.values(schema.model.entities)
	const allFields = (e: any, value: any) => Object.fromEntries(Object.keys(e.fields).map(f => [f, value]))
	const reader: any = { variables: {}, stages: '*', entities: {} }
	const writer: any = { variables: {}, stages: '*', entities: {} }
	for (const e of entities) {
		const isArticle = e.name === 'Article'
		reader.entities[e.name] = {
			predicates: isArticle ? { published: { published: { eq: true } } } : {},
			operations: { read: allFields(e, isArticle ? 'published' : true) },
		}
		writer.entities[e.name] = {
			predicates: {},
			operations: {
				read: allFields(e, true),
				create: allFields(e, true),
				update: allFields(e, true),
				delete: true,
			},
		}
	}
	return { ...schema, acl: { ...schema.acl, roles: { sonda_reader: reader, writer } } }
})

const differ = new SchemaDiffer(new SchemaMigrator(new ModificationHandlerFactory(ModificationHandlerFactory.defaultFactoryMap)))
const modifications = differ.diffSchemas(emptySchema, schema)
const name = '2026-10-24-120000-init'
// Printed as a complete System API request body, so dev/seed-contember.sh can POST it with plain curl.
console.log(JSON.stringify({
	query: 'mutation($migrations: [Migration!]!) { migrate(migrations: $migrations) { ok error { code developerMessage } } }',
	variables: { migrations: [{ formatVersion: VERSION_LATEST, version: name.slice(0, 17), name, modifications }] },
}, null, '\t'))
