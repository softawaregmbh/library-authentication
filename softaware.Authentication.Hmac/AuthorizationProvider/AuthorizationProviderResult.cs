using System;
using System.Collections.Generic;

namespace softaware.Authentication.Hmac.AuthorizationProvider
{
    public readonly struct AuthorizationProviderResult
    {
        public AuthorizationProviderResult(string appId, bool found, string apiKey)
        {
            this.AppId = appId;
            this.Found = found;
            this.ApiKey = apiKey;
            this.ApiKeys = apiKey != null ? new[] { apiKey } : [];
        }

        /// <summary>
        /// Initializes a new instance with multiple API keys to support key rotation.
        /// During key rotation, both old and new keys can be provided so that requests
        /// signed with either key are accepted.
        /// </summary>
        public AuthorizationProviderResult(string appId, bool found, IReadOnlyList<string> apiKeys)
        {
            this.AppId = appId;
            this.Found = found;
            this.ApiKeys = apiKeys ?? Array.Empty<string>();
            this.ApiKey = this.ApiKeys.Count > 0 ? this.ApiKeys[0] : null;
        }

        /// <summary>
        /// The HMAC App Id.
        /// </summary>
        public string AppId { get; }

        /// <summary>
        /// <see langword="True"/>, if the specified HMAC app has been found based on the <see cref="AppId"/>.
        /// </summary>
        public bool Found { get; }

        /// <summary>
        /// The primary API key for the specified <see cref="AppId"/>.
        /// When multiple keys are configured, this returns the first key.
        /// </summary>
        public string ApiKey { get; }

        /// <summary>
        /// All valid API keys for the specified <see cref="AppId"/>.
        /// Supports key rotation by allowing multiple keys to be accepted simultaneously.
        /// </summary>
        public IReadOnlyList<string> ApiKeys { get; }
    }
}
