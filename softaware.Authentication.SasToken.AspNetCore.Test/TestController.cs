using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace softaware.Authentication.SasToken.AspNetCore.Test
{
    [Route("api/[controller]")]
    [Authorize]
    public class TestController : Controller
    {
        public ActionResult Index([FromQuery] string? parameter)
        {
            return this.Ok(parameter);
        }

        [Route("Name")]
        public ActionResult GetName()
        {
            return this.Ok(this.User.Identity?.Name);
        }
    }
}
