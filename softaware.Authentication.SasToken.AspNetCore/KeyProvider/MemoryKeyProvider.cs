namespace softaware.Authentication.SasToken.AspNetCore.KeyProvider
{
    public class MemoryKeyProvider : IKeyProvider
    {
        private readonly string key;

        public MemoryKeyProvider(string key)
        {
            this.key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public Task<string> GetKeyAsync()
        {
            return Task.FromResult(this.key);
        }
    }
}
