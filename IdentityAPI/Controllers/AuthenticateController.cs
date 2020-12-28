using IdentityAPI.Core.Models;
using IdentityAPI.Core.Models.Authentication;
using IdentityAPI.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace IdentityAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class AuthenticateController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthenticateController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
             IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [AllowAnonymous]
        [ValidationFilter]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddDays(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                    );

                var userRoles = await _userManager.GetRolesAsync(user);

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }

            return Unauthorized();
        }

        [AllowAnonymous]
        [ValidationFilter]
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            var user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, result.Errors);
            else
            {
                if (!_roleManager.RoleExistsAsync(IdentityAPI.Core.Roles.UserRoles.User).Result)
                {
                    var role = new ApplicationRole() { Name = IdentityAPI.Core.Roles.UserRoles.User };

                    var roleResult = await _roleManager.CreateAsync(role);
                    if (roleResult.Succeeded)
                        _userManager.AddToRoleAsync(user, IdentityAPI.Core.Roles.UserRoles.User).Wait();
                }
                else
                    _userManager.AddToRoleAsync(user, IdentityAPI.Core.Roles.UserRoles.User).Wait();
            }

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        [AllowAnonymous]
        [ValidationFilter]
        [HttpPost]
        [Route("Register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

            var user = new ApplicationUser()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError, result.Errors);

            if (!await _roleManager.RoleExistsAsync(IdentityAPI.Core.Roles.UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(IdentityAPI.Core.Roles.UserRoles.Admin));
            if (!await _roleManager.RoleExistsAsync(IdentityAPI.Core.Roles.UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(IdentityAPI.Core.Roles.UserRoles.User));

            if (await _roleManager.RoleExistsAsync(IdentityAPI.Core.Roles.UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, IdentityAPI.Core.Roles.UserRoles.Admin);
            }

            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

    }
}
