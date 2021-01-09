using IdentityAPI.Core.Models;
using IdentityAPI.Core.Models.Authentication;
using System.Threading.Tasks;

namespace IdentityAPI.Core.Service
{
    public interface IAuthService<TEntity> where TEntity : class
    {
        Task<TEntity> LoginWithRules(LoginModel model);

        Task<TEntity> PasswordReset(ResetPasswordModel model);

        Task<TEntity> UpdatePassword(UpdatePasswordModel model, string userId, string token);

        //Task<TEntity> RegisterUser(RegisterModel model);
    }
}
