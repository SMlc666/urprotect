# State Management

## Scope

There is no frontend state-management library or browser state in the current
repository. Validation and pack results are immutable C# records returned from
Core services, and `ProductReportFactory` projects them into JSON for CLI
consumers.

Do not add a client store to represent parser state. If a UI is introduced,
create a task defining local, URL, server/report, and shared application state,
plus the single decoder/reducer that owns each event or report contract.
