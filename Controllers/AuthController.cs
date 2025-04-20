
using JWTRefreshToken.DTOs;
using JWTRefreshToken.Models;
using JWTRefreshToken.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticattionTemplete__JWT_.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService authService;

        public AuthController(IAuthService authService)
        {
            this.authService = authService;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegisterDTO registerDTO)
        {
            if(!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await authService.Register(registerDTO);
            if(result.Message != null)
                return BadRequest(result.Message);
            
            AddRefreshTokenToCookie(result.RefreshToken, result.RefreshTokenExpiresOn);
            return Ok(result);
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginDTO loginDTO)
        {
            if (!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await authService.Login(loginDTO);
            if (result.Message != null)
                return BadRequest(result.Message);

            if(!string.IsNullOrEmpty(result.RefreshToken))
                AddRefreshTokenToCookie(result.RefreshToken, result.RefreshTokenExpiresOn);

            return Ok(result);
        }

        [HttpPost("AsssignToRole")]
        public async Task<IActionResult> AssignToRole(AssignToRoleDTO assignToRoleDTO)
        {
            if(!ModelState.IsValid)
                return BadRequest(ModelState);
            var result = await authService.AssignToRole(assignToRoleDTO);
            if(result != null)
                return BadRequest(result);
            return Ok();
        }

        [HttpGet("RefreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest();

            var result = await authService.RefreshToken(refreshToken); 

            if(result.Message != null)
                return BadRequest(result.Message);

            AddRefreshTokenToCookie(result.RefreshToken, result.RefreshTokenExpiresOn);

            return Ok(result);

        }

        [HttpGet("RevokeToken")]
        public async Task<IActionResult> RevokeToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];

            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest();

            var result = await authService.RevokeToken(refreshToken);

            if(!result)
                return BadRequest("Invalid Token");

            return Ok();

        }

        private void AddRefreshTokenToCookie(string refreshToken, DateTime expires)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Expires = expires,
            };

            Response.Cookies.Append("refreshToken", refreshToken, cookieOptions);
        }
    }
}
