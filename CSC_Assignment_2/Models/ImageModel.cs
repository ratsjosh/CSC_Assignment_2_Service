using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Models
{
    public class ImageModel
    {
        public string Id { get; set; }

        public string ImageBase64 { get; set; }

        public List<string> ListOfBase64 { get; set; }

    }
}
