using IdentityAPI.Core.Constants;
using IdentityAPI.Core.Models;
using IdentityAPI.Core.Models.Authentication;
using IdentityAPI.Core.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Mail;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using IdentityAPI.Core.Utils;

namespace IdentityAPI.Service
{
    public class AuthService : IAuthService<Response>
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager,
             IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<Response> LoginWithRules(LoginModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null)
                return new Response() { Status = (int)ResultStatus.Result.ERROR, Message = "User not found" };
            else
            {
                var checkPassword = await _userManager.CheckPasswordAsync(user, model.Password);

                if (checkPassword)
                {
                    await _userManager.ResetAccessFailedCountAsync(user); //Önceki hataları girişler neticesinde +1 arttırılmış tüm değerleri 0(sıfır)a çekiyoruz.

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

                    return new Response()
                    {
                        Status = (int)ResultStatus.Result.SUCCESS,
                        Token = new JwtSecurityTokenHandler().WriteToken(token),
                        Expiration = token.ValidTo
                    };
                }
                else
                {
                    await _userManager.AccessFailedAsync(user); //Eğer ki başarısız bir account girişi söz konusu ise AccessFailedCount kolonundaki değer +1 arttırılacaktır. 

                    int failcount = await _userManager.GetAccessFailedCountAsync(user); //Kullanıcının yapmış olduğu başarısız giriş deneme adedini alıyoruz.

                    return new Response()
                    {
                        Status = (int)ResultStatus.Result.ERROR,
                        Message = failcount == 3 ? "" : "E-posta veya şifre yanlış"
                    };
                }
            }
        }

        public async Task<Response> PasswordReset(ResetPasswordModel model)
        {
            if (!string.IsNullOrEmpty(model.Email))
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    string resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

                    var mailMessage = new MailMessage();
                    mailMessage.IsBodyHtml = true;
                    mailMessage.To.Add(user.Email);
                    mailMessage.From = new MailAddress("wouwcharming@gmail.com", "Şifre Güncelleme", System.Text.Encoding.UTF8);
                    mailMessage.Subject = "Şifre Güncelleme Talebi";
                    mailMessage.Body = "https://localhost:5001/UpdatePassword/" + Extension.EncodeText(user.Id) + "/" + Extension.EncodeText(resetToken);
                    mailMessage.IsBodyHtml = true;

                    var smp = new SmtpClient();
                    smp.Credentials = new NetworkCredential("wouwcharming@gmail.com", "Test6677?");
                    smp.Port = 587;
                    smp.Host = "smtp.gmail.com";
                    smp.EnableSsl = true;
                    smp.UseDefaultCredentials = false;

                    try
                    {
                        smp.Send(mailMessage);

                        return new Response() { Status = (int)ResultStatus.Result.SUCCESS, Message = "Sended email" };

                    }
                    catch (Exception ex)
                    {
                        return new Response() { Status = (int)ResultStatus.Result.ERROR, Message = "Could not send an email " + ex.Message };
                    }
                }
            }

            return new Response() { Status = (int)ResultStatus.Result.ERROR, Message = "User email is empty" };
        }

        public async Task<Response> UpdatePassword(UpdatePasswordModel model, string userId, string token)
        {
            if (!(string.IsNullOrEmpty(userId) && string.IsNullOrEmpty(token)))
            {
                var user = await _userManager.FindByIdAsync(Extension.DecodeText(userId));
                if (user != null)
                {
                    IdentityResult result = await _userManager.ResetPasswordAsync(user, Extension.DecodeText(token), model.Password);

                    if (result.Succeeded)
                        return new Response() { Status = (int)ResultStatus.Result.SUCCESS, Message = "Updated password" };
                    else
                        return new Response() { Status = (int)ResultStatus.Result.ERROR, Message = "Error updating password" };
                }
                else
                    return new Response() { Status = (int)ResultStatus.Result.ERROR, Message = "User not found" };
            }

            return new Response() { Status = (int)ResultStatus.Result.ERROR, Message = "User id and token is null" };
        }

        private bool _isRegisteredUser(string mail)
        {
            if (string.IsNullOrEmpty(mail))
                return false;

            var user = _userManager.FindByEmailAsync(mail);

            if (user == null)
                return false;

            return true;
        }


    }
}
