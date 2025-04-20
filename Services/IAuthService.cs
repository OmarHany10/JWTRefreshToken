using JWTRefreshToken.DTOs;

namespace JWTRefreshToken.Services
{
    public interface  IAuthService
    {
        Task<UserDTO> Register(RegisterDTO registerDTO);

        Task<UserDTO> Login(LoginDTO loginDTO);

        Task<string> AssignToRole(AssignToRoleDTO assignToRoleDTO);

        Task<UserDTO> RefreshToken(string token);

        Task<bool> RevokeToken(string token);
    }
}
