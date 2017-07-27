using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class TokenProviderOptions
    {
        public string Path { get; set; } = "/token";

        public string Issuer { get; set; } = "Issuer";

        public string Audience { get; set; } = "Audience";

        public TimeSpan Expiration { get; set; } = TimeSpan.FromMinutes(500);

        public SigningCredentials SigningCredentials { get; set; }
    }
}
