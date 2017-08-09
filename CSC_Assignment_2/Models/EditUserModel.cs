using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class EditUserModel
    {
        public EditUserModel(string id, string name, string email, string reknown, string bio)
        {
            Id = id;
            Name = name;
            Email = email;
            Reknown = reknown;
            Bio = bio;
        }
        public string Id { get; set; }
        public string Name { get; set; }
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        public string Reknown { get; set; }
        public string Bio { get; set; }
    }
}
