using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace softaware.Authentication.Hmac.AspNetCore.Test
{
    [Route("api/[controller]")]
    [Authorize]
    public class TestController : Controller
    {
        public ActionResult Index()
        {
            return this.Ok();
        }

        [Route("Name")]
        public ActionResult GetName()
        {
            return this.Ok(this.User.Identity.Name);
        }

        [Route("Claims")]
        public ActionResult GetClaims()
        {
            return this.Ok(this.User.Claims.Select(p => new { Name = p.Type, Value = p.Value }));
        }
    }
}
