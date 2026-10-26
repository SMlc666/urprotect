# Hook Guidelines

## Scope

There are no frontend hooks, data-fetching hooks, browser APIs, or reactive
client lifecycle code in this repository. `NoOpPipeline` is a synchronous C#
pipeline, not a frontend hook.

If a frontend is added, document hook ownership and naming in a dedicated task.
Hooks should consume a typed report/event boundary rather than re-parsing JSON
fields independently in every component.
