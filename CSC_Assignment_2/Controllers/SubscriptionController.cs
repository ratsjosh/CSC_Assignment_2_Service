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
    [Authorize(ActiveAuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
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
        public async Task<bool> CreateSubscriptionAsync(SubscriptionViewModel svm)
        {
            try
            {
                StripeServices ss = new StripeServices();
                string id = ss.CreateSubscription(svm.price, svm.name, svm.interval.ToLower());
                SubscriptionModel sm = new SubscriptionModel();
                sm.IdToken = id;
                sm.IsActive = svm.status;
                _applicationDbContext.SubscriptionModel.Add(sm);
                await _applicationDbContext.SaveChangesAsync();
                return true;

            }
            catch (Exception e) {
                return false;
            }
        }

        [HttpPut]
        public async Task<bool> ChangePlanStatusAsync(string id, bool status)
        {
            try
            {
                var plan = _applicationDbContext.SubscriptionModel.Where(p => p.IdToken == id).First();
                plan.IsActive = status;
                _applicationDbContext.SubscriptionModel.Update(plan);
                await _applicationDbContext.SaveChangesAsync();
                return true;

            }
            catch (Exception e)
            {
                return false;
            }
        }

        [HttpPut]
        public bool UpdateSubscription(string planId, string name)
        {
            StripeServices ss = new StripeServices();
            try
            {
                SubscriptionModel sm = _applicationDbContext.SubscriptionModel.Where(t => t.IdToken == planId).First();
                if (sm != null)
                {
                    ss.UpdateSubscription(planId, name);
                    return true;
                }
                else {
                    throw new Exception();
                }
            } catch (Exception e) {
                return false;
            }
        }


    }
}