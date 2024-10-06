using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RoleBaseJWTProject.Dtos;
using RoleBaseJWTProject.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace RoleBaseJWTProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost("signup")]
        public async Task<IActionResult> SignUp(SignUpDto dto)
        {
            var user = new ApplicationUser
            {
                UserName = dto.Username,
                Email = dto.Email,
            };
            var result = await _userManager.CreateAsync(user, dto.Password);
            if (result.Succeeded)
            {
                if (!await _roleManager.RoleExistsAsync("Admin"))
                {
                    await _roleManager.CreateAsync(new IdentityRole("Admin"));
                }

                await _userManager.AddToRoleAsync(user, "Admin");

                return Ok(new { Status = "Success", Message = "Admin created successfully!" });
            }

            return BadRequest(new { Status = "Error", Message = "Admin creation failed!", Errors = result.Errors });
        }

        [Authorize(Roles ="Admin")]
        [HttpPost("signup-client")]
        public async Task<IActionResult> SignUpClient([FromBody]SignUpDto dto)
        {
            var user = new ApplicationUser
            {
                UserName = dto.Username,
                Email = dto.Email,
            };
            var result = await _userManager.CreateAsync(user, dto.Password);
            if (result.Succeeded)
            {
                if (!await _roleManager.RoleExistsAsync("Client"))
                {
                    await _roleManager.CreateAsync(new IdentityRole("Client"));
                }

                await _userManager.AddToRoleAsync(user, "Client");

                return Ok(new { Status = "Success", Message = "Client created successfully!" });
            }

            return BadRequest(new { Status = "Error", Message = "User creation failed!", Errors = result.Errors });
        }

        [HttpPost("signin")]
        public async Task<IActionResult> SignIn([FromBody] SignInDto dto)
        {
            var user = await _userManager.FindByNameAsync(dto.Username);

            if(user!=null && await _userManager.CheckPasswordAsync(user, dto.Password))
            {
                var userRoles=await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                };

                foreach (var role in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, role));
                }

                var token = GetToken(authClaims);

                return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token) ,Expiration=token.ValidTo}); 
            }
            
            return Unauthorized();
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Issuer"],
                expires:DateTime.Now.AddHours(3),
                claims:authClaims,
                signingCredentials:new SigningCredentials(authSigninKey,SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
    }
}
