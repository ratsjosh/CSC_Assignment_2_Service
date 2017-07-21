using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class ImageModel
    {
        public string userId { get; set; }

        public string base64 { get; set; }

        public List<string> ListOfBase64 { get; set; }

    }
}
