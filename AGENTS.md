# Coding Agent Onboarding Guide

## Repository Overview

This repository contains .NET authentication libraries for ASP.NET Core, published as NuGet packages by softaware gmbh. It provides three authentication schemes:

- **HMAC** – HMAC-based request signing authentication
- **Basic** – HTTP Basic authentication
- **SasToken** – Shared Access Signature (SAS) token authentication

## Project Structure

```
softaware.Authentication.sln          # Visual Studio solution (all projects)
softaware.Authentication.Hmac/        # Core HMAC types and utilities
softaware.Authentication.Hmac.AspNetCore/   # ASP.NET Core AuthenticationHandler for HMAC
softaware.Authentication.Hmac.Client/       # DelegatingHandler for HMAC client-side signing
softaware.Authentication.Hmac.AspNetCore.Test/  # Integration tests for HMAC
softaware.Authentication.Hmac.Benchmarks/   # BenchmarkDotNet benchmarks (not run as tests)
softaware.Authentication.Basic/             # Core Basic auth types
softaware.Authentication.Basic.AspNetCore/  # ASP.NET Core AuthenticationHandler for Basic
softaware.Authentication.Basic.Client/      # DelegatingHandler for Basic client-side auth
softaware.Authentication.Basic.AspNetCore.Test/  # Integration tests for Basic
softaware.Authentication.SasToken/          # Core SAS token types (generation, validation)
softaware.Authentication.SasToken.AspNetCore/    # ASP.NET Core AuthenticationHandler for SasToken
softaware.Authentication.SasToken.AspNetCore.Test/ # Integration tests for SasToken
Assets/                                    # Shared assets (NuGet package icon)
```

## Build

The solution targets **.NET 8**. Library projects multi-target `netstandard2.0;net6.0;net8.0`; test projects target `net8.0` only. Any .NET SDK version that supports `net8.0` targets (SDK 8.x or later) will work; the sandbox environment uses SDK 10.x.

```sh
# Build entire solution (Release configuration, also generates .nupkg files)
dotnet build --configuration Release

# Build a specific project
dotnet build softaware.Authentication.Hmac.AspNetCore/softaware.Authentication.Hmac.AspNetCore.csproj --configuration Release
```

The build produces `.nupkg` files alongside each library project (controlled by `<GeneratePackageOnBuild>true</GeneratePackageOnBuild>` in `.csproj`).

## Test

Tests use **xunit** with `Microsoft.AspNetCore.Mvc.Testing` for integration-style middleware tests. There are no unit tests outside of the integration test projects.

```sh
# Run all tests
dotnet test --configuration Release

# Run tests for a specific project
dotnet test softaware.Authentication.Hmac.AspNetCore.Test/softaware.Authentication.Hmac.AspNetCore.Test.csproj --configuration Release
```

All tests should pass with `0 Failed`. Expected totals on a clean run:
- `softaware.Authentication.Hmac.AspNetCore.Test`: ~41 tests
- `softaware.Authentication.Basic.AspNetCore.Test`: ~20 tests
- `softaware.Authentication.SasToken.AspNetCore.Test`: ~13 tests

## CI/CD

The CI pipeline is defined in `azure-pipelines.yml` and runs on Azure DevOps (not GitHub Actions). It:
1. Installs .NET 8
2. Runs `dotnet build --configuration Release`
3. Runs `dotnet test --configuration Release --logger trx`
4. Publishes test results (`.trx` files)
5. Publishes `.nupkg` build artifacts

## Key Conventions

- **Language version**: `LangVersion=Latest` is set in all library project files.
- **Namespace**: All public types use the `softaware.Authentication.<Module>[.<SubModule>]` namespace pattern.
- **Interfaces for extensibility**: Each authentication module exposes an interface (`IHmacAuthorizationProvider`, `IBasicAuthorizationProvider`, `IKeyProvider`) so consumers can supply custom implementations. Built-in in-memory providers (`MemoryHmacAuthenticationProvider`, `MemoryBasicAuthenticationProvider`, `MemoryKeyProvider`) are provided for convenience.
- **DelegatingHandler clients**: Client-side authentication adds authorization headers via a `DelegatingHandler` subclass (e.g., `ApiKeyDelegatingHandler` for HMAC, `BasicAuthenticationDelegatingHandler` for Basic).
- **Versioning**: NuGet package versions are set directly in each `.csproj` file via the `<Version>` element.
- **No linter / code style tool** is configured in this repo. Follow existing code style (4-space indentation, standard C# naming conventions).

## Test Project Patterns

Each `*.Test` project follows the same structure:
- `TestStartup.cs` – configures the ASP.NET Core middleware pipeline for tests
- `TestWebApplicationFactory.cs` – `WebApplicationFactory<TestStartup>` subclass
- `TestController.cs` – minimal controller used as test endpoint
- `MiddlewareTest.cs` – xunit test class with `[Theory]`/`[Fact]` tests using the factory

When adding tests, follow this same structure.

## Known Build Warnings

The following compiler warnings are present in the codebase and are pre-existing (not caused by your changes):

- `CS9113: Parameter 'env' is unread` in `TestStartup.cs` files of all three test projects. These are benign and expected.

## Errors and Workarounds

No errors were encountered during initial exploration. `dotnet build` and `dotnet test` both succeed out of the box on a Linux environment with the .NET 10 SDK (which is backward-compatible for building .NET 8 targets).
