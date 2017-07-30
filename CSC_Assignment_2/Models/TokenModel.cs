using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class TokenModel
    {
        public TokenModel(string accessToken)
        {
            AccessToken = accessToken;
        }
        public string AccessToken { get; set; }
    }
}
