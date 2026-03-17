# Entry Point Mapper Agent

## Task
Find ALL network-accessible entry points in the codebase. Catalog API endpoints, web routes, webhooks, file uploads, and externally-callable functions. ALSO identify and catalog API schema files (OpenAPI/Swagger *.json/*.yaml/*.yml, GraphQL *.graphql/*.gql, JSON Schema *.schema.json) that document these endpoints. Distinguish between public endpoints and those requiring authentication. Exclude local-only dev tools, CLI scripts, and build processes. Provide exact file paths and route definitions for both endpoints and schemas.

## Working Directory
/app/repos/lumin-20260315-052139-18638

## Requirements
1. Find all HTTP endpoints (controllers, routes, handlers)
2. Identify authentication-required vs public endpoints
3. Find API schema/documentation files
4. Map web routes to handler methods
5. Include exact file paths with line numbers
6. Apply the Master Scope Definition: only include network-reachable components
