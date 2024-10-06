using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace RoleBaseJWTProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class HomeController : ControllerBase
    {
        [HttpGet("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminEndPoint()
        {
            return Ok("Hello Admin , this is your dashboard");
        }

        [HttpGet("client")]
        [Authorize(Roles = "Client")]
        public IActionResult ClientEndPoint()
        {
            return Ok("Hello Client , this is your dashboard");
        }
    }
}
