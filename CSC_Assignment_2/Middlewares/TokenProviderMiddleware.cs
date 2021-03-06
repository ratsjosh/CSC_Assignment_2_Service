﻿using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class TokenProviderMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly TokenProviderOptions _options;
        private readonly UserManager<ApplicationUser> _userManager;

        public TokenProviderMiddleware(
        RequestDelegate next,
        IOptions<TokenProviderOptions> options,
        UserManager<ApplicationUser> userManager)
        {
            _next = next;
            _options = options.Value;
            _userManager = userManager;
        }

        public Task Invoke(HttpContext context)
        {
            // If the request path doesn't match, skip
            if (!context.Request.Path.Equals(_options.Path, StringComparison.Ordinal))
            {
                return _next(context);
            }

            // Request must be POST with Content-Type: application/x-www-form-urlencoded
            if (!context.Request.Method.Equals("POST")
 || !context.Request.HasFormContentType)
            {
                context.Response.StatusCode = 400;
                return context.Response.WriteAsync("Bad request.");
            }

            return GenerateToken(context);
        }

        private async Task GenerateToken(HttpContext context)
        {
            var username = context.Request.Form["username"];
            var password = context.Request.Form["password"];
            var captcha = context.Request.Form["captcha"];
            
            if (!String.IsNullOrEmpty(captcha) && !await CheckCaptchaAsync(captcha))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Capatcha is not valid!");
                return;
            }

            var identity = await GetIdentityAsync(username, password);
            if (identity == null)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid username or password.");
                return;
            }

            var account = VerifyEmail(identity);
            if (account.Result == null)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Email has not been verified.");
                return;
            }

            var now = DateTime.UtcNow;
            long ToUnixEpochDate(DateTime date) => new DateTimeOffset(date).ToUniversalTime().ToUnixTimeSeconds();
            // Specifically add the jti (random nonce), iat (issued timestamp), and sub (subject/user) claims.
            // You can add other claims here, if you want:
            var claims = new Claim[]
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(now).ToString(), ClaimValueTypes.Integer64)
        };

            // Create the JWT and write it to a string
            var jwt = new JwtSecurityToken(

            issuer: _options.Issuer,
            audience: _options.Audience,
            claims: claims,
            notBefore: now,
            expires: now.Add(_options.Expiration),
            signingCredentials: _options.SigningCredentials);
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            LoginModel lm = new LoginModel { Email = username, AccessToken = encodedJwt, ExpirationDate = DateTime.Now.AddSeconds((int)_options.Expiration.TotalSeconds) };
            var response = new
            {
                access_token = encodedJwt,
                expires_in = (int)_options.Expiration.TotalSeconds,
                loginModel = lm
            };

            //CookieOptions options = new CookieOptions();
            //options.Expires = DateTime.Now.AddDays(response.expires_in);
            //context.Response.Cookies.Append("Token", response.access_token, options);

            Startup._sessionDbcontext.PostAsync(lm);

            // Serialize and return the response
            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, new JsonSerializerSettings { Formatting = Formatting.Indented }));
        }
        private async Task<ApplicationUser> GetIdentityAsync(string username, string password)
        {
            var user = await _userManager.FindByEmailAsync(username);
            if (user != null)
            {
                if (await _userManager.CheckPasswordAsync(user, password))
                {
                    return user;
                }
            }
            // Credentials are invalid, or account doesn't exist
            return null;
        }

        private async Task<ClaimsIdentity> VerifyEmail(ApplicationUser user)
        {
            if (user.EmailConfirmed)
            {
                return await Task.FromResult(new ClaimsIdentity(new System.Security.Principal.GenericIdentity(user.UserName, "Token"), new Claim[] { }));
            }
            // Credentials are invalid, or account doesn't exist
            return await Task.FromResult<ClaimsIdentity>(null);
        }

        private async Task<bool> CheckCaptchaAsync(string captcha)
        {
            try
            {
                HttpClient client = new HttpClient();

                var values = new Dictionary<string, string>
                {
                   { "secret", "6LfvbSwUAAAAADf2tvnH_xhdYPMllULz9xdFfcrg" },
                   { "response", captcha }
                };

                var content = new FormUrlEncodedContent(values);

                var response = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", content);
                dynamic CaptchaResponse = JsonConvert.DeserializeObject(await response.Content.ReadAsStringAsync());

                return CaptchaResponse.success;
            }
            catch
            {
                return false;
            }
        }
    }
}
