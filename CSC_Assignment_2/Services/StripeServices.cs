using Stripe;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Services
{
    public class StripeServices
    {

        public StripeServices() {
            StripeConfiguration.SetApiKey("sk_test_7jStegpTg5BoZBswviBiAfV0");
        }

        public string CreateSubscription(int cost, string planName) {
            string id = new Guid().ToString();
            var newPlan = new StripePlanCreateOptions();
            newPlan.Id = id;
            newPlan.Amount = cost;           // all amounts on Stripe are in cents, pence, etc
            newPlan.Currency = "usd";        // "usd" only supported right now
            newPlan.Interval = "month";      // "month" or "year"
            newPlan.Name = planName;

            var planService = new StripePlanService();
            StripePlan response = planService.Create(newPlan);
            return id;
        }

        public void UpdateSubscription(string id, string planName, int cost = 0)
        {
            if (cost == 0)
            {
                var updatedPlan = new StripePlanUpdateOptions();

                updatedPlan.Name = planName;

                var planService = new StripePlanService();
                StripePlan response = planService.Update(id, updatedPlan);
            }
            else
            {
                string newId = CreateSubscription(cost, planName);
                StripePlanService plan = new StripePlanService();
                

            }
        }

    }
}
