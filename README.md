# softaware.Authentication

<!-- TOC -->

  - [softaware.Authentication.Hmac](#softawareauthenticationhmac)
      - [softaware.Authentication.Hmac.AspNetCore](#softawareauthenticationhmacaspnetcore)
      - [softaware.Authentication.Hmac.Client](#softawareauthenticationhmacclient)
      - [Generate HMAC AppId and ApiKey](#generate-hmac-appid-and-apikey)
  - [softaware.Authentication.Basic](#softawareauthenticationbasic)
      - [softaware.Authentication.Basic.AspNetCore](#softawareauthenticationbasicaspnetcore)
      - [softaware.Authentication.Basic.Client](#softawareauthenticationbasicclient)

<!-- /TOC -->

## softaware.Authentication.Hmac

### softaware.Authentication.Hmac.AspNetCore

Provides an [`AuthenticationHandler`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhandler-1?view=aspnetcore-2.1) which supports [HMAC](https://en.wikipedia.org/wiki/HMAC) authentication in an ASP.NET Core project.

Usage:

1. Get your HMAC authenticated clients, for example from the `appsettings.json` file. For HMAC authentication, an `AppId` and an `ApiKey` is required for each client which should get access.

```csharp
var hmacAuthenticatedApps = this.Configuration
    .GetSection("Authentication")
    .GetSection("HmacAuthenticatedApps")
    .Get<HmacAuthenticationClientConfiguration[]>()
    .ToDictionary(e => e.AppId, e => e.ApiKey);
```

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

2. Enable HMAC authentication in `Startup.cs` in the `ConfigureServices` method:

```csharp
services
    .AddAuthentication(o =>
    {
        o.DefaultScheme = HmacAuthenticationDefaults.AuthenticationScheme;
    })
    .AddHmacAuthentication(HmacAuthenticationDefaults.AuthenticationScheme, "HMAC Authentication", o =>
    {
        o.MaxRequestAgeInSeconds = HmacAuthenticationDefaults.MaxRequestAgeInSeconds;
        o.HmacAuthenticatedApps = hmacAuthenticatedApps;
    });
```

3. Add `MemoryCache` (from [Microsoft.Extensions.Caching.Memory](https://www.nuget.org/packages/Microsoft.Extensions.Caching.Memory/)) in `Startup.cs` in the `ConfigureServices` method.
The `MemoryCache` is used by the HMAC `AuthenticationHandler` to determine replay attacks.

```csharp
services.AddMemoryCache();
```

4. Enable authentication in `Startup.cs` in the `Configure` method:

```csharp
app.UseAuthentication();
```

5. Optional: Specify HMAC as the authentication scheme for certain controllers:

```csharp
[Authorize(AuthenticationSchemes = HmacAuthenticationDefaults.AuthenticationScheme)]
[Route("api/[controller]")]
public class HomeController : Controller
{
   // ...
}
```

### softaware.Authentication.Hmac.Client

Provides a `DelegatingHandler` for adding an HMAC authorization header to HTTP requests.

Instantiate your `HttpClient` instance with the `ApiKeyDelegatingHandler`.
Make sure, that you don't create new `HttpClient` instances for every request (see also [this blog post](https://aspnetmonsters.com/2016/08/2016-08-27-httpclientwrong/) for details):

```csharp
new HttpClient(new ApiKeyDelegatingHandler(appId, apiKey));
```

Or in case your WebAPI client is another ASP.NET WebAPI (>= [ASP.NET Core 2.1](https://docs.microsoft.com/en-us/dotnet/api/microsoft.extensions.dependencyinjection.httpclientfactoryservicecollectionextensions.addhttpclient?view=aspnetcore-2.1)), register your `HttpClient` in the `Startup.cs` for example as follows:

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

Provides an [`AuthenticationHandler`](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhandler-1?view=aspnetcore-2.1) which supports [Basic](https://en.wikipedia.org/wiki/Basic_access_authentication) authentication in an ASP.NET Core project.

Enable Basic authentication in `Startup.cs` in the `ConfigureServices` method:

```csharp
services.AddAuthentication(o =>
    {
        o.DefaultScheme = BasicAuthenticationDefaults.AuthenticationScheme;
    })
    .AddBasicAuthentication(BasicAuthenticationDefaults.AuthenticationScheme, o =>
    {
        o.AuthorizationProvider = new MemoryBasicAuthenticationProvider(authenticatedApps);
    });
```

### softaware.Authentication.Basic.Client

Provides a `DelegatingHandler` for adding an HMAC authorization header to HTTP requests.

Instantiate your `HttpClient` instance with the `BasicAuthenticationDelegatingHandler`.
Make sure, that you don't create new `HttpClient` instances for every request (see also [this blog post](https://aspnetmonsters.com/2016/08/2016-08-27-httpclientwrong/) for details):

```csharp
new HttpClient(new BasicAuthenticationDelegatingHandler(username, password));
```