using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using CSC_Assignment_2.Services;
using CSC_Assignment_2.Models;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Configuration;

namespace CSC_Assignment_2.Controllers
{
    //[Authorize(ActiveAuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    //[Route("api/Subscription")]
    public class SubscriptionController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<ApplicationRole> _roleManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ISmsSender _smsSender;
        private readonly string _externalCookieScheme;
        private readonly IConfiguration _configuration;

        public SubscriptionController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<ApplicationRole> roleManager,
            IOptions<IdentityCookieOptions> identityCookieOptions,
            IEmailSender emailSender,
            ISmsSender smsSender,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _externalCookieScheme = identityCookieOptions.Value.ExternalCookieAuthenticationScheme;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _configuration = configuration;
        }
        [HttpPost]
        public string CreateSubscription()
        {
            StripeServices ss = new StripeServices();
            ss.CreateSubscription(0, "");
            return null;
        }

        [HttpPost]
        public string AccountSubscription()
        {
            return null;
        }

        [HttpPut]
        public string UpdateSubscription()
        {
            return null;
        }
    }
}