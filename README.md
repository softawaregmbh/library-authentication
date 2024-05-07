# softaware.Authentication

<!-- TOC -->

- [softaware.Authentication](#softawareauthentication)
  - [softaware.Authentication.Hmac](#softawareauthenticationhmac)
    - [softaware.Authentication.Hmac.AspNetCore](#softawareauthenticationhmacaspnetcore)
    - [softaware.Authentication.Hmac.Client](#softawareauthenticationhmacclient)
    - [Generate HMAC AppId and ApiKey](#generate-hmac-appid-and-apikey)
  - [softaware.Authentication.Basic](#softawareauthenticationbasic)
    - [softaware.Authentication.Basic.AspNetCore](#softawareauthenticationbasicaspnetcore)
    - [softaware.Authentication.Basic.Client](#softawareauthenticationbasicclient)
  - [softaware.Authentication.SasToken](#softawareauthenticationsastoken)
    - [softaware.Authentication.SasToken.AspNetCore](#softawareauthenticationsastokenaspnetcore)

<!-- /TOC -->

## softaware.Authentication.Hmac

### softaware.Authentication.Hmac.AspNetCore

[![Nuget](https://img.shields.io/nuget/v/softaware.Authentication.Hmac.AspNetCore)](https://www.nuget.org/packages/softaware.Authentication.Hmac.AspNetCore)

Provides an [`AuthenticationHandler`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhandler-1) which supports [HMAC](https://en.wikipedia.org/wiki/HMAC) authentication in an ASP.NET Core project.

Usage:

1. Register an implementation of `IHmacAuthorizationProvider` in `Startup.cs`. Either use the built-in `MemoryHmacAuthenticationProvider` for in-memory HMAC app configuration or implement your own `IHmacAuthorizationProvider` to provide HMAC apps.
   
    ```csharp
    services.AddTransient<IHmacAuthorizationProvider>(_ => new MemoryHmacAuthenticationProvider(hmacAuthenticatedApps));
    ```

2. When using the built-in `MemoryHmacAuthenticationProvider`, get your HMAC authenticated clients, for example from the `appsettings.json` file. For HMAC authentication, an `AppId` and an `ApiKey` is required for each client which should get access.

    ```json
    {
      "Authentication": {
        "HmacAuthenticatedApps": [
            {
                "AppId": "<some-app-id>",
                "ApiKey": "<some-api-key>"
            }
        ]
      }
    }
    ```

    ```csharp
    var hmacAuthenticatedApps = this.Configuration
        .GetSection("Authentication")
        .GetSection("HmacAuthenticatedApps")
        .Get<HmacAuthenticationClientConfiguration[]>()
        .ToDictionary(e => e.AppId, e => e.ApiKey);
    ```

3. Enable HMAC authentication in `Startup.cs` in the `ConfigureServices` method. The `.AddHmacAuthentication(...)` method will use the configured `IHmacAuthorizationProvider` for resolving HMAC apps:

    ```csharp
    services
        .AddAuthentication(o =>
        {
            o.DefaultScheme = HmacAuthenticationDefaults.AuthenticationScheme;
        })
        .AddHmacAuthentication(HmacAuthenticationDefaults.AuthenticationScheme, "HMAC Authentication", options => { });
    ```

4. Add `MemoryCache` (from [Microsoft.Extensions.Caching.Memory](https://www.nuget.org/packages/Microsoft.Extensions.Caching.Memory/)) in `Startup.cs` in the `ConfigureServices` method.
The `MemoryCache` is used by the HMAC `AuthenticationHandler` to determine replay attacks.

    ```csharp
    services.AddMemoryCache();
    ```

5. Enable authentication in `Startup.cs` in the `Configure` method:

    ```csharp
    app.UseAuthentication();
    ```

6. Optional: Specify HMAC as the authentication scheme for certain controllers:

    ```csharp
    [Authorize(AuthenticationSchemes = HmacAuthenticationDefaults.AuthenticationScheme)]
    [Route("api/[controller]")]
    public class HomeController : Controller
    {
       // ...
    }
    ```

### softaware.Authentication.Hmac.Client

[![Nuget](https://img.shields.io/nuget/v/softaware.Authentication.Hmac.Client)](https://www.nuget.org/packages/softaware.Authentication.Hmac.Client)

Provides a `DelegatingHandler` for adding an HMAC authorization header to HTTP requests.

Instantiate your `HttpClient` instance with the `ApiKeyDelegatingHandler`.
Make sure, that you don't create new `HttpClient` instances for every request (see also [this blog post](https://aspnetmonsters.com/2016/08/2016-08-27-httpclientwrong/) for details):

```csharp
new HttpClient(new ApiKeyDelegatingHandler(appId, apiKey));
```

Or in case your WebAPI client is another ASP.NET WebAPI (>= [ASP.NET Core 2.1](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.httpclientfactoryservicecollectionextensions.addhttpclient)), register your `HttpClient` in the `Startup.cs` for example as follows:

```csharp
services.AddTransient(sp => new ApiKeyDelegatingHandler(appId, apiKey));

services
    .AddHttpClient("HmacHttpClient")
    .AddHttpMessageHandler<ApiKeyDelegatingHandler>();
```

### Generate HMAC AppId and ApiKey

To generate an API Key, the following simple Console Application can be used.
This implementation is also provided on [.NET Fiddle](https://dotnetfiddle.net/hJcYB2).

```csharp
using System.Security.Cryptography;

public class Program
{
    public static void Main()
    {
        Console.WriteLine($"AppID: {Guid.NewGuid()} or <some-speaking-name>");
        Console.WriteLine($"ApiKey: {GenerateApiKey()}");
    }

    private static string GenerateApiKey()
    {
        using (var cryptoProvider = new RNGCryptoServiceProvider())
        {
            byte[] secretKeyByteArray = new byte[32]; //256 bit
            cryptoProvider.GetBytes(secretKeyByteArray);
            return Convert.ToBase64String(secretKeyByteArray);
        }
    }
}

```

## softaware.Authentication.Basic

### softaware.Authentication.Basic.AspNetCore

[![Nuget](https://img.shields.io/nuget/v/softaware.Authentication.Basic.AspNetCore)](https://www.nuget.org/packages/softaware.Authentication.Basic.AspNetCore)

Provides an [`AuthenticationHandler`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhandler-1) which supports [Basic](https://en.wikipedia.org/wiki/Basic_access_authentication) authentication in an ASP.NET Core project.

Enable Basic authentication in `Startup.cs` in the `ConfigureServices` method:

```csharp
services.AddTransient<IBasicAuthorizationProvider>(_ => new MemoryBasicAuthenticationProvider(authenticatedApps));

services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = BasicAuthenticationDefaults.AuthenticationScheme;
    })
    .AddBasicAuthentication();
```

If you want to validate usernames and passwords from the basic authentication header more sophisticated than the built-in `MemoryBasicAuthenticationProvider`, just implement and register your own `IBasicAuthorizationProvider`.

Enable Authentication in `Startup.cs` in the `Configure` method:
```csharp
app.UseAuthentication();
```

### softaware.Authentication.Basic.Client

[![Nuget](https://img.shields.io/nuget/v/softaware.Authentication.Basic.Client)](https://www.nuget.org/packages/softaware.Authentication.Basic.Client)

Provides a `DelegatingHandler` for adding an HMAC authorization header to HTTP requests.

Instantiate your `HttpClient` instance with the `BasicAuthenticationDelegatingHandler`.
Make sure, that you don't create new `HttpClient` instances for every request (see also [this blog post](https://aspnetmonsters.com/2016/08/2016-08-27-httpclientwrong/) for details):

```csharp
new HttpClient(new BasicAuthenticationDelegatingHandler(username, password));
```

## softaware.Authentication.SasToken

### softaware.Authentication.SasToken.AspNetCore

[![Nuget](https://img.shields.io/nuget/v/softaware.Authentication.SasToken.AspNetCore)](https://www.nuget.org/packages/softaware.Authentication.SasToken.AspNetCore)

Provides an [`AuthenticationHandler`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhandler-1) which supports Shared Access Signature (SAS) authentication in an ASP.NET Core project.

Enable SAS authentication in `Startup.cs` in the `ConfigureServices` method:

```csharp
services.AddTransient<IKeyProvider>(_ => new MemoryKeyProvider(key));

services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = SasTokenAuthenticationDefaults.AuthenticationScheme;
    })
    .AddSasTokenAuthentication();
```

If you want to retrieve the key for the shared access signature other than from the built-in `MemoryKeyProvider`, you can implement and register your own `IKeyProvider`.

Enable Authentication in `Startup.cs` in the `Configure` method:
```csharp
app.UseAuthentication();
```

To generate an URL with a Shared Access Signature, inject the `SasTokenUrlGenerator` and call the `GenerateSasTokenQueryStringAsync(...)` method for getting the SAS query string or `GenerateSasTokenUriAsync(...)` method to receive the full SAS URI.