﻿using System.Collections.Generic;
using System.Linq;
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
                this.credentials.TryGetValue(username, out var secureString) &&
                password == secureString);
        }
    }
}
