﻿using Microsoft.EntityFrameworkCore;

namespace JWTRefreshToken.Models
{
    [Owned]
    public class RefreshToken
    {
        public string Token { get; set; }
        public DateTime ExpiresOn { get; set; }
        public DateTime CreatedOn { get; set; }
        public DateTime RevokedOn { get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiresOn;

    }
}
