using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace JWTRefreshToken.Models
{
    public class ApplicationUser:IdentityUser
    {
        public string? Address {  get; set; }

        public IList<RefreshToken> RefreshTokens { get; set; }
    }
}
