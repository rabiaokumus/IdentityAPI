using IdentityAPI.Core.Constants;
using IdentityAPI.Core.Models;
using IdentityAPI.Core.Models.Authentication;
using IdentityAPI.Core.Service;
using IdentityAPI.Filters;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace IdentityAPI.Controllers
{
    [Authorize]
    [ApiController]
    //[Route("[controller]")]
    public class AuthenticateController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IAuthService<Response> _authService;

        public AuthenticateController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
             IConfiguration configuration,
             IAuthService<Response> authService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _authService = authService;
        }

        [AllowAnonymous]
        [ValidationFilter]
        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var result = await _authService.LoginWithRules(model);

            if (result.Status == (int)ResultStatus.Result.ERROR)
                return StatusCode(StatusCodes.Status401Unauthorized, result);
            else
                return StatusCode(StatusCodes.Status200OK, result);
        }


        [AllowAnonymous]
        [ValidationFilter]
        [HttpPost]
        [Route("ResetPassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            var result = await _authService.PasswordReset(model);

            if (result.Status == (int)ResultStatus.Result.ERROR)
                return BadRequest(result);
            else
                return StatusCode(StatusCodes.Status200OK, result);
        }


        [AllowAnonymous]
        [ValidationFilter]
        [HttpPost]
        [Route("UpdatePassword/{userId}/{token}")]
        public async Task<IActionResult> UpdatePassword([FromBody] UpdatePasswordModel model, string userId, string token)
        {
            var result = await _authService.UpdatePassword(model, userId, token);

            if (result.Status == (int)ResultStatus.Result.ERROR)
                return BadRequest(result);
            else
                return StatusCode(StatusCodes.Status200OK, result);
        }


        [AllowAnonymous]
        [ValidationFilter]
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = (int)ResultStatus.Result.ERROR, Message = "User already exists!" });

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

            return Ok(new Response { Status = (int)ResultStatus.Result.SUCCESS, Message = "User created successfully!" });
        }

        [AllowAnonymous]
        [ValidationFilter]
        [HttpPost]
        [Route("Register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            var userExists = await _userManager.FindByNameAsync(model.Email);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = (int)ResultStatus.Result.ERROR, Message = "User already exists!" });

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

            return Ok(new Response { Status = (int)ResultStatus.Result.SUCCESS, Message = "User created successfully!" });
        }
    }
}
