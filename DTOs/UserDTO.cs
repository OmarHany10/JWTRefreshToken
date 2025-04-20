using System.Text.Json.Serialization;

namespace JWTRefreshToken.DTOs
{
    public class UserDTO
    {
        public string Token { get; set; }
        //public DateTime ValidTO { get; set; }
        public string Message { get; set; }

        [JsonIgnore]
        public string? RefreshToken { get; set; }

        public DateTime RefreshTokenExpiresOn { get; set; }
    }
}
