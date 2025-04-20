using System.ComponentModel.DataAnnotations;

namespace JWTRefreshToken.DTOs
{
    public class AssignToRoleDTO
    {
        [Required]
        public string UserId { get; set; }
        
        [Required]
        public string RoleName { get; set; }
    }
}
