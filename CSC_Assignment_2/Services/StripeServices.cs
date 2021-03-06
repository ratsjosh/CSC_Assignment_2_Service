﻿using CSC_Assignment_2.Models;
using Stripe;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Services
{
    public class StripeServices
    {

        public StripeServices()
        {
            StripeConfiguration.SetApiKey("sk_test_7jStegpTg5BoZBswviBiAfV0");
        }

        public string CreateSubscription(int cost, string planName, string interval)
        {
            string id = Guid.NewGuid().ToString();
            var newPlan = new StripePlanCreateOptions();
            newPlan.Id = id;
            newPlan.Amount = cost;           // all amounts on Stripe are in cents, pence, etc
            newPlan.Currency = "usd";        // "usd" only supported right now
            newPlan.Interval = interval;      // "month" or "year"
            newPlan.Name = planName;

            var planService = new StripePlanService();
            StripePlan response = planService.Create(newPlan);
            return id;
        }

        public void UpdateSubscription(string id, string planName)
        {

            var updatedPlan = new StripePlanUpdateOptions();

            updatedPlan.Name = planName;

            var planService = new StripePlanService();
            StripePlan response = planService.Update(id, updatedPlan);

        }

        public void UnsubscribePlan(string customerId)
        {
            var customerService = new StripeCustomerService();
            StripeCustomer stripeCustomer = customerService.Get(customerId);
            var subscriptionId = stripeCustomer.Subscriptions.First().Id;

            var subscriptionService = new StripeSubscriptionService();
            subscriptionService.Cancel(subscriptionId);
        }

        public string CreateStripeCustomer(string tokenId, string planId, ApplicationUser user)
        {

            var myCustomer = new StripeCustomerCreateOptions();
            myCustomer.Email = user.Email;
            myCustomer.SourceToken = tokenId;
            myCustomer.PlanId = planId;                          // only if you have a plan
            myCustomer.Quantity = 1;                               // optional, defaults to 1

            var customerService = new StripeCustomerService();
            StripeCustomer stripeCustomer = customerService.Create(myCustomer);

            return stripeCustomer.Id;
        }

        public StripePlan GetUserPlan(string customerId)
        {
            var customerService = new StripeCustomerService();
            StripeCustomer stripeCustomer = customerService.Get(customerId);
            return stripeCustomer.Subscriptions.First().StripePlan;
        }

        public string ChangeAccountPlan(string planId, string customerId)
        {
            var customerService = new StripeCustomerService();
            StripeCustomer stripeCustomer = customerService.Get(customerId);
            var subscriptionId = stripeCustomer.Subscriptions.First().Id;

            var subscriptionService = new StripeSubscriptionService();
            StripeSubscriptionUpdateOptions ssuo = new StripeSubscriptionUpdateOptions();
            ssuo.PlanId = planId;

            StripeSubscription stripeSubscription = subscriptionService.Update(subscriptionId, ssuo);

            return null;
            // optional StripeSubscriptionUpdateOptions            return null;
        }

        public string SubscribeAccountPlan(string planId, string customerId)
        {
            var subscriptionService = new StripeSubscriptionService();
            StripeSubscription stripeSubscription = subscriptionService.Create(customerId, planId);
            return null;
            // optional StripeSubscriptionUpdateOptions            return null;
        }

        public void CreateCard(string customerId, string tokenId)
        {
            var myCard = new StripeCardCreateOptions();

            myCard.SourceToken = tokenId;

            var cardService = new StripeCardService();
            StripeCard stripeCard = cardService.Create(customerId, myCard); // optional isRecipient
        }

        public IEnumerable<StripePlan> GetAllPlans()
        {
            var planService = new StripePlanService();
            return planService.List();
        }

        public void TransferSubscription(string id)
        {
            var planService = new StripePlanService();
            StripePlan response = planService.Get(id);
        }

    }
}
