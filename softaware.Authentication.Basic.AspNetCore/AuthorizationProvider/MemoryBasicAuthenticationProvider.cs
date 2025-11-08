using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace softaware.Authentication.Basic.AspNetCore.AuthorizationProvider
{
    public class MemoryBasicAuthenticationProvider : IBasicAuthorizationProvider
    {
        private readonly IReadOnlyDictionary<string, string> credentials;

        public MemoryBasicAuthenticationProvider(IReadOnlyDictionary<string, string> credentials)
        {
            this.credentials = credentials.ToDictionary(c => c.Key, c => c.Value);
        }

        public Task<bool> IsAuthorizedAsync(string username, string password)
        {
            return Task.FromResult(
                this.credentials.TryGetValue(username, out var storedPassword) &&
                EqualsFixedLength(password, storedPassword));
        }

        private static bool EqualsFixedLength(string storedPassword, string inputPassword)
            => CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(storedPassword), Encoding.UTF8.GetBytes(inputPassword));
    }
}
