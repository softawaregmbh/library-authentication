using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace softaware.Authentication.Basic.AspNetCore.AuthorizationProvider;

public class MemoryBasicAuthenticationProvider(IReadOnlyDictionary<string, string> credentials) : IBasicAuthorizationProvider
{
    private readonly Dictionary<string, string> credentials = credentials.ToDictionary(c => c.Key, c => c.Value);

    public Task<bool> IsAuthorizedAsync(string username, string password)
    {
        return Task.FromResult(
            this.credentials.TryGetValue(username, out var secureString) &&
            password == secureString);
    }
}
