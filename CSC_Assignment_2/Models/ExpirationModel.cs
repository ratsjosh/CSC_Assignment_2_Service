using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class ExpirationModel
    {

        [Required]
        public string AccessToken { get; set; }

        [Required]
        public DateTime ExpirationDate { get; set; }
    }
}
