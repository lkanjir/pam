# Backend development

Use the .NET 10 SDK and Docker for integration tests. Run these commands from the
repository root:

```sh
dotnet build src/Backend/Backend.sln
dotnet test src/Backend/Backend.sln --no-build
```

See [test coverage and conventions](tests/README.md) for details.

## C# formatting

The root `.editorconfig` is the shared source of formatting preferences:

- Four spaces, UTF-8, LF, final newline, no trailing whitespace.
- Allman braces (opening brace on a new line); compact auto-properties are allowed.
- File-scoped namespaces and `using` directives outside the namespace.
- A 120-character line-length target. Rider wraps long parameter/argument lists
  one item per line and indents continuations rather than aligning them in columns.
- Existing deliberate line breaks are preserved. Braces for control statements
  are suggested; `var` is preferred for inferred object types, explicit types for primitives.
- Project/build files, JSON and YAML use two spaces.

Rider reads EditorConfig by default, and configured properties override its local
preferences. Use **Reformat Code** to apply them. If a file still looks different,
use **Show Code Style Configuration** in Find Action to inspect which settings
apply. See [Rider's EditorConfig documentation](https://www.jetbrains.com/help/rider/Using_EditorConfig.html)
and its [wrapping settings](https://www.jetbrains.com/help/rider/EditorConfig_CSHARP_LineBreaksPageSchema.html).

Apply or verify the shared whitespace rules from the CLI:

```sh
dotnet format whitespace src/Backend/Backend.sln --no-restore --exclude src/Backend/Infrastructure/Persistence/Migrations
dotnet format whitespace src/Backend/Backend.sln --no-restore --exclude src/Backend/Infrastructure/Persistence/Migrations --verify-no-changes
```

`dotnet format` handles Roslyn formatting rules; Rider-specific wrapping and
alignment settings are applied by Rider. It does not enforce the 120-character
limit or every syntax-style suggestion. EF migration files are generated code
and excluded from routine formatting.

## Build and packages

`Directory.Build.props` defines the shared target framework, nullable context and
implicit usings. `Directory.Packages.props` owns NuGet versions; project files list
package references without versions. Change versions centrally when upgrading.

Docker builds use the repository root as their context so these files are included:

```sh
docker build -f src/Backend/Dockerfile --target final -t pam-api .
docker build -f src/Backend/Dockerfile --target migrator -t pam-migrator .
```

The Compose configuration uses the same context. The root `.dockerignore` allows
only backend source and shared build files, excluding build output and `.env` files.
