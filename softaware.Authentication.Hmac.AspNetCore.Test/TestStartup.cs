using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace softaware.Authentication.Hmac.AspNetCore.Test
{
    public class TestStartup
    {
        public TestStartup(IWebHostEnvironment env)
        {
        }

        /// <summary>
        ///  This method gets called by the runtime. Use this method to add services to the container.
        /// </summary>
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc().AddApplicationPart(typeof(TestController).Assembly);

            services.AddAuthorization();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory, IHostApplicationLifetime appLifetime)
        {
            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(options =>
            {
                options
                    .MapControllers();
            });
        }
    }
}
