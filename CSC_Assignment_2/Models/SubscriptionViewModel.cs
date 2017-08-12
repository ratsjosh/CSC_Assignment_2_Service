using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class SubscriptionViewModel
    {
        public string id { get; set; }
        public string interval { get; set; }
        public string name { get; set; }
        public int price { get; set; }
        public bool status { get; set; }
    }
}
