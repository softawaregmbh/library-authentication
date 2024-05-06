namespace softaware.Authentication.SasToken.KeyProvider
{
    public class MemoryKeyProvider : IKeyProvider
    {
        private readonly string key;

        public MemoryKeyProvider(string key)
        {
            this.key = key ?? throw new ArgumentNullException(nameof(key));
        }

        public Task<string> GetKeyAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(this.key);
        }
    }
}
