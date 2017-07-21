using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System;

namespace CSC_Assignment_2.Models
{
    public class ApplicationRole : IdentityRole
    {
        public string Description { get; set; }
        public DateTime CreatedDate { get; set; }
        public string IPAddress { get; set; }
    }
}
