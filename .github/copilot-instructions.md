# Copilot Instructions for Coraza WAF

## Project Overview

Coraza is a Web Application Firewall (WAF) engine written in Go that implements Seclang directives and it is compatible with OWASP CRS. It provides protection against common web application attacks.

## Code Style and Conventions

### General Go Guidelines
- Follow standard Go conventions and idioms
- Use `gofmt` and `golint` for code formatting
- Prefer clear, readable code over clever but hard-to-understand optimizations
- Use meaningful variable and function names
- Keep functions small and focused on a single responsibility

### Naming Conventions
- Use camelCase for variables and functions (e.g., `ruleset`, `parseRule`)
- Use PascalCase for exported types and functions (e.g., `WAF`, `Transaction`)
- Use ALL_CAPS for constants
- Use descriptive names for collections (e.g., `rules []Rule` not `r []Rule`)

### Error Handling
- Always check and handle errors explicitly
- Never use panic in library code
- Wrap errors with context using `fmt.Errorf("context: %w", err)` as much as possible
- Use custom error types for domain-specific errors
- Log errors at appropriate levels (debug, info, warn, error) and avoid interpolations

### Comments and Documentation
- Add package-level documentation for all packages
- Document all exported functions, types, and variables
- Use complete sentences in comments
- Start comments with the name of the item being documented
- Include examples in documentation when appropriate

## Project-Specific Guidelines

### WAF Rules and Directives
- Rules should be immutable after compilation
- Support all ModSecurity directives when possible
- Validate rule syntax during parsing
- Provide clear error messages for invalid rules

### Transaction Processing
- Transactions must be concurrent-safe
- Each transaction should have its own isolated state
- Clean up resources after transaction completion
- Support interruption (block/drop) at any phase
- Log all rule matches and anomalies

### Performance Considerations
- **Be obsessed about performance in critical paths and memory leaks**
- Avoid excessive locking in hot paths
- Avoid unnecessary allocations in hot paths
- Use object pooling for frequently created objects (e.g., transactions)
- Profile and benchmark code before optimizing, focus on real bottlenecks and impactful optimizations (in the order of microseconds rather than nanoseconds)
- Use efficient data structures (prefer maps for lookups)
- Minimize the overhead of rule evaluation and only evaluate necessary rules

### Testing
- Write table-driven tests for functions with multiple cases
- Use subtests with `t.Run()` for logical grouping
- Mock external dependencies
- Aim for high test coverage on critical paths
- Include both positive and negative test cases
- Test edge cases and error conditions

### Security
- Never log sensitive data (passwords, tokens, session IDs)
- Validate all inputs
- Use constant-time comparisons for security-sensitive operations
- Be cautious with regex that could cause ReDoS
- Follow secure coding practices for WAF operations

### Concurrency
- When implementing concurrency, be mindful about the tinygo environment and its limitations and use build tags if necessary
- Use mutexes to protect shared state
- Prefer channels for communication between goroutines
- Document thread-safety guarantees
- Avoid deadlocks by maintaining consistent lock ordering
- Use `sync.Pool` for object reuse

## File Organization

- Organize code by functionality
- All packages should be internal unless they are part of the public API
- Use the `experimental/` directory for experimental features
- Keep tests in the same package as the code being tested
- Use subdirectories for large packages to improve organization

## Dependencies

- Minimize external dependencies
- Prefer standard library when possible
- Document why each dependency is needed
- Keep dependencies up to date
- Use Go modules for dependency management

## Common Patterns


### Variable Expansion
- Support ModSecurity variable syntax (e.g., `%{TX.anomaly_score}`)
- Handle collections and specific fields
- Implement proper escaping

## Anti-Patterns to Avoid

- Don't use global mutable state
- Avoid reflection in performance-critical code
- Don't ignore errors
- Avoid long parameter lists (use structs or options pattern)
- Don't mix business logic with I/O operations

## ModSecurity Compatibility

- Maintain compatibility with ModSecurity v2/v3 where possible
- Document any intentional deviations
- Support OWASP CRS directives
- Implement standard actions (block, pass, deny, drop, etc.)
- Support standard operators (rx, eq, contains, etc.)

## Logging

- Use structured logging
- Include relevant context (transaction ID, rule ID, etc.)
- Use appropriate log levels
- Don't log in tight loops
- Make logging configurable

## When Adding New Features

1. Come up with a solid use case with more than one potential user
2. Document the feature
3. Update relevant examples
4. Keep backward compatibility
