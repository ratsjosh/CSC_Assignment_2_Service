using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Amazon.Runtime;
using Amazon.DynamoDBv2;
using Microsoft.Extensions.Configuration;
using Amazon.DynamoDBv2.Model;
using System.Threading;
using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;
using CSC_Assignment_2.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using System.Security.Principal;

namespace CSC_Assignment_2.Controllers
{

    [Authorize(ActiveAuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class SessionController : Controller
    {
        //private BasicAWSCredentials _credentials;
        //private AmazonDynamoDBClient _client;
        private readonly IConfiguration _configuration;
        //private DynamoDBContext _context;

        public SessionController(
            IConfiguration configuration)
        {
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> UpdateSessionExpirationByAccessTokenAsync([FromBody]TokenModel token)
        {
            if (ModelState.IsValid)
            {

                List<ScanCondition> conditions = new List<ScanCondition>();
                conditions.Add(new ScanCondition("AccessToken", ScanOperator.Equal, token.AccessToken));
                List<LoginModel> result = await Startup._sessionDbcontext._context.ScanAsync<LoginModel>(conditions).GetRemainingAsync();
                LoginModel model = result.FirstOrDefault();
                model.SessionExpiration = token.SessionExpiration;
                await Startup._sessionDbcontext._context.SaveAsync(model);
                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult AuthenticateJwtToken([FromBody]TokenModel token)
        {
            string username = "";
            if (ValidateToken(token.AccessToken, out username))
            {
                // based on username to get more information from database in order to build local identity
                var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, username)
                // Add more claims if needed: Roles, ...
            };

                var identity = new ClaimsIdentity(claims, "Jwt");
                IPrincipal user = new ClaimsPrincipal(identity);

                return Ok(Json(new { isAuthenticated = user.Identity.IsAuthenticated }));
            }

            return BadRequest(Json(new { isAuthenticated = false }));
        }

        private ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

                if (jwtToken == null)
                    return null;

                string secretKey = _configuration.GetSection("TokenConfiguration")["SecretKey"].ToString();
                SymmetricSecurityKey signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

                var validationParameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = signingKey
                };

                SecurityToken securityToken;
                var principal = tokenHandler.ValidateToken(token, validationParameters, out securityToken);

                return principal;
            }

            catch (Exception ex)
            {
                //should write log
                string exception = ex.Message;
                return null;
            }
        }

        private bool ValidateToken(string token, out string username)
        {
            username = null;

            var simplePrinciple = GetPrincipal(token);
            if (simplePrinciple == null)
                return false;
            var identity = simplePrinciple.Identity as ClaimsIdentity;

            if (identity == null)
                return false;

            if (!identity.IsAuthenticated)
                return false;

            var usernameClaim = identity.FindFirst(ClaimTypes.Name);
            username = usernameClaim?.Value;

            if (string.IsNullOrEmpty(username))
                return false;

            // More validate to check whether username exists in system

            return true;
        }

        // GET: api/Session/GetUserByEmailAsync
        /// <summary>
        /// Get user by the access token
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<LoginModel> GetUserByEmailAsync()
        {
            string email = Request.Headers["Email"];
            if (!string.IsNullOrEmpty(email))
            {
                List<ScanCondition> conditions = new List<ScanCondition>();
                conditions.Add(new ScanCondition("Email", ScanOperator.Equal, email));
                List<LoginModel> result = await Startup._sessionDbcontext._context.ScanAsync<LoginModel>(conditions).GetRemainingAsync();
                LoginModel authenticateLoginModel = null;
                foreach (LoginModel lm in result)
                {
                    string username = "";
                    if (ValidateToken(lm.AccessToken, out username))
                    {
                        var claims = new List<Claim>
                        {
                            new Claim(ClaimTypes.Name, username)
                            // Add more claims if needed: Roles, ...
                        };

                        var identity = new ClaimsIdentity(claims, "Jwt");
                        IPrincipal user = new ClaimsPrincipal(identity);
                        if (user.Identity.IsAuthenticated)
                        {
                            authenticateLoginModel = lm;
                            break;
                        }
                    }
                }
                return authenticateLoginModel;
            }
            else
            {
                return null;
            }
        }

        // GET: api/Session/GetUserByAccessTokenAsync
        /// <summary>
        /// Get user by the access token
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        [HttpGet]
        public async Task<LoginModel> GetUserByAccessTokenAsync()
        {
            string accessToken = Request.Headers["AccessToken"];
            if (!string.IsNullOrEmpty(accessToken))
            {
                List<ScanCondition> conditions = new List<ScanCondition>();
                conditions.Add(new ScanCondition("AccessToken", ScanOperator.Equal, accessToken));
                List<LoginModel> result = await Startup._sessionDbcontext._context.ScanAsync<LoginModel>(conditions).GetRemainingAsync();
                return result.FirstOrDefault();
            }
            else
            {
                return null;
            }
        }

        // POST: api/Session
        [HttpPost]
        public async Task<IActionResult> PostAsync([FromBody]LoginModel model)
        {
            if (ModelState.IsValid)
            {
                await Startup._sessionDbcontext._context.SaveAsync(model);
                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }

        // DELETE: api/ApiWithActions/5
        [HttpDelete]
        public async Task<IActionResult> DeleteByAccessTokenAsync(string accessToken)
        {
            if (!string.IsNullOrEmpty(accessToken))
            {
                List<ScanCondition> conditions = new List<ScanCondition>();
                conditions.Add(new ScanCondition("AccessToken", ScanOperator.Equal, accessToken));
                List<LoginModel> result = await Startup._sessionDbcontext._context.ScanAsync<LoginModel>(conditions).GetRemainingAsync();
                await Startup._sessionDbcontext._context.DeleteAsync(result.FirstOrDefault());
                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }
    }
}
