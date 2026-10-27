# Frontend Type Safety

## Scope

No TypeScript or other frontend type system is present. Production type safety
is currently provided by C# nullable reference types, immutable records, enums,
and typed diagnostic/address models; see `src/UrProtect.Core/` and the backend
quality guide.

Do not create frontend DTOs by independently casting JSON report fields. A
future frontend must define one typed report decoder at the CLI/API boundary,
validate untrusted JSON at runtime, and keep shared report types separate from
component-local view models.
