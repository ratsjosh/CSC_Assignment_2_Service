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
using CSC_Assignment_2.Data;

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
        private readonly ApplicationDbContext _applicationDbContext;

        public SubscriptionController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<ApplicationRole> roleManager,
            IOptions<IdentityCookieOptions> identityCookieOptions,
            IEmailSender emailSender,
            ISmsSender smsSender,
            IConfiguration configuration,
            ApplicationDbContext applicationDbContext)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _externalCookieScheme = identityCookieOptions.Value.ExternalCookieAuthenticationScheme;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _configuration = configuration;
            _applicationDbContext = applicationDbContext;
        }

        [HttpPost]
        public IActionResult CreateSubscription([FromBody]SubscriptionViewModel svm)
        {
            try
            {
                StripeServices ss = new StripeServices();
                string id = ss.CreateSubscription(svm.price, svm.name);
                SubscriptionModel sm = new SubscriptionModel();
                sm.IdToken = id;
                sm.IsActive = svm.status;
                _applicationDbContext.SubscriptionModel.Add(sm);
                _applicationDbContext.SaveChanges();
                return Ok();

            }
            catch (Exception e) {
                return BadRequest();
            }
        }

        [HttpPut]
        public IActionResult UpdateSubscription([FromBody]SubscriptionViewModel svm)
        {
            StripeServices ss = new StripeServices();
            try
            {
                SubscriptionModel sm = _applicationDbContext.SubscriptionModel.Where(t => t.IdToken == svm.id).First();
                if (sm != null)
                {
                    ss.UpdateSubscription(svm.id, svm.name);
                    sm.IsActive = svm.status;
                    _applicationDbContext.SubscriptionModel.Update(sm);
                    _applicationDbContext.SaveChanges();
                    return Ok();
                }
                else {
                    throw new Exception();
                }
            } catch (Exception e) {
                return BadRequest();
            }
        }


    }
}