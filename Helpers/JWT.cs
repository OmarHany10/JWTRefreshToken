﻿namespace JWTRefreshToken.Helpers
{
    public class JWT
    {
        public string Key { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int Duration { get; set; }
    }
}
