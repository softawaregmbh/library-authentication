using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace softaware.Authentication.Basic.Client
{
    public class BasicAuthenticationDelegatingHandler : DelegatingHandler
    {
        private readonly string username;
        private readonly string password;

        public BasicAuthenticationDelegatingHandler(string username, string password)
        {
            this.username = username ?? throw new ArgumentNullException(nameof(username));
            this.password = password ?? throw new ArgumentNullException(nameof(password));
        }

        public BasicAuthenticationDelegatingHandler(string username, string password, HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            this.username = username ?? throw new ArgumentNullException(nameof(username));
            this.password = password ?? throw new ArgumentNullException(nameof(password));
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic",
                Convert.ToBase64String(Encoding.ASCII.GetBytes(string.Format("{0}:{1}", this.username, this.password))));

            return base.SendAsync(request, cancellationToken);
        }
    }
}
