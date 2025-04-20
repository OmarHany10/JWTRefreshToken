using JWTRefreshToken.DTOs;
using JWTRefreshToken.Helpers;
using JWTRefreshToken.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace JWTRefreshToken.Services
{
    public class AuthService: IAuthService
    {
        private readonly UserManager<ApplicationUser> userManager;
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly JWT jWT;

        public AuthService(UserManager<ApplicationUser> userManager, IOptions<JWT> _JWT, RoleManager<IdentityRole> roleManager)
        {
            this.userManager = userManager;
            this.roleManager = roleManager;
            jWT = _JWT.Value;
        }

        public async Task<UserDTO> Register(RegisterDTO registerDTO) 
        {
            if (await userManager.FindByNameAsync(registerDTO.Username) is not null)
                return new UserDTO{ Message = "This Username already token" };
            if (await userManager.FindByEmailAsync(registerDTO.Email) is not null)
                return new UserDTO { Message = "This Email already token" };
            ApplicationUser user = new ApplicationUser()
            {
                UserName = registerDTO.Username,
                Email = registerDTO.Email,
                Address = registerDTO.Address,
            };

            IdentityResult result = await userManager.CreateAsync(user, registerDTO.Password);
            if (!result.Succeeded)
            {
                string errors = "";
                foreach (var error in result.Errors)
                {
                    errors += $"{error.Description}, ";
                }
                return new UserDTO { Message = errors };
            }

            // Generate Token

            var jwtSecurityToken = await CreateToken(user);

            string token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);

            var userDTO = new UserDTO { Token = token, /*ValidTO = jwtSecurityToken.ValidTo */ };
            return userDTO;
        }

        public async Task<UserDTO> Login(LoginDTO loginDTO)
        {
            ApplicationUser user = await userManager.FindByNameAsync(loginDTO.Username);
            if (user == null)
                return new UserDTO { Message = "Incorrect Username or Password" };
            bool result = await userManager.CheckPasswordAsync(user, loginDTO.Password);
            if(!result)
                return new UserDTO { Message = "Incorrect Username or Password" };

            //Generate Token
            var jwtSecurityToken = await CreateToken(user);

            string token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            var userDTO = new UserDTO { Token = token, /* ValidTO = jwtSecurityToken.ValidTo */ };

            var activeRefreshToken = user.RefreshTokens.FirstOrDefault();
            if (activeRefreshToken == null)
            {
                var refreshToken = GenerateRefreshToken();
                userDTO.RefreshToken = refreshToken.Token;
                userDTO.RefreshTokenExpiresOn = refreshToken.ExpiresOn;
                user.RefreshTokens.Add(refreshToken);
                await userManager.UpdateAsync(user);
            }
            else
            {
                userDTO.RefreshToken = activeRefreshToken.Token;
                userDTO.RefreshTokenExpiresOn = activeRefreshToken.ExpiresOn;
            }

            return userDTO;
        }

        private async Task<JwtSecurityToken> CreateToken(ApplicationUser user)
        {
            var userClaims = await userManager.GetClaimsAsync(user);
            var UserRoles = await userManager.GetRolesAsync(user);
            var UserRoleClaims = new List<Claim>();
            foreach (var userRole in UserRoles)
            {
                UserRoleClaims.Add(new Claim("role", userRole));
            }

            var Claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("uid", user.Id),
            }.Union(userClaims).Union(UserRoleClaims);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jWT.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jWT.Issuer,
                audience: jWT.Audience,
                claims: Claims,
                expires: DateTime.Now.AddMinutes(jWT.Duration),
                signingCredentials: signingCredentials
                );
            
            return token;
        }

        public async Task<string> AssignToRole(AssignToRoleDTO assignToRoleDTO)
        {
            var user = await userManager.FindByIdAsync(assignToRoleDTO.UserId);
            if (user == null)
                return "Incorrect User Id";
            if (!await roleManager.RoleExistsAsync(assignToRoleDTO.RoleName))
                return "Incorrect Role Name";
            if (await userManager.IsInRoleAsync(user, assignToRoleDTO.RoleName))
                return $"User already assigned to {assignToRoleDTO.RoleName} role";

            var result = await userManager.AddToRoleAsync(user, assignToRoleDTO.RoleName);

            return result.Succeeded ? null : $"Error : {result.Errors.ToString()}";
        }


        private RefreshToken GenerateRefreshToken()
        {
            var random = new byte[32];
            using var generator = new RNGCryptoServiceProvider();
            generator.GetBytes(random);
            return new RefreshToken 
            {
                Token = Convert.ToBase64String(random),
                CreatedOn = DateTime.Now,
                ExpiresOn = DateTime.Now.AddDays(5),
            };
        }

        public async Task<UserDTO> RefreshToken(string token)
        {

            var user =  await userManager.Users.FirstOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
            if(user == null)
                return new UserDTO{Message = "Invalid Token"};

            var refreshToken = user.RefreshTokens.FirstOrDefault(t => t.Token == token);

            if(refreshToken.IsExpired)
                return new UserDTO { Message = "Invalid Token" };

            refreshToken.RevokedOn = DateTime.UtcNow;
            
            var newRefreshToken = GenerateRefreshToken();
            user.RefreshTokens.Add(newRefreshToken);
            await userManager.UpdateAsync(user);

            var jWTToken = await CreateToken(user);

            var userDTO = new UserDTO
            {
                Token = new JwtSecurityTokenHandler().WriteToken(jWTToken),
                RefreshToken = newRefreshToken.Token,
                RefreshTokenExpiresOn = newRefreshToken.ExpiresOn
            };

            return userDTO;

        }

        public async Task<bool> RevokeToken(string token)
        {
            var user = await userManager.Users.FirstOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));
            if (user == null)
                return false;

            var refreshToken = user.RefreshTokens.FirstOrDefault(t => t.Token == token);

            if (refreshToken.IsExpired)
                return false;

            refreshToken.RevokedOn = DateTime.UtcNow;

            await userManager.UpdateAsync(user);

            return true;
        }
    }
}
