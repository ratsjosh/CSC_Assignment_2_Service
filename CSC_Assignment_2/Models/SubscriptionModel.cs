using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class SubscriptionModel
    {
        [Key]
        public string IdToken { get; set; }
        public bool IsActive { get; set; }

    }
}
