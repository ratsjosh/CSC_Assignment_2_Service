using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace CSC_Assignment_2.Models
{
    // Add profile data for application users by adding properties to the ApplicationUser class
    public class ApplicationUser : IdentityUser
    {

        [Required(ErrorMessage = "Name attribute is required")]
        public string Name { get; set; }
        public string Reknown { get; set; }
        public string Bio { get; set; }
        public string ProfilePictureImage { get; set; }
        //public string StripeToken { get; set; }

    }
}
