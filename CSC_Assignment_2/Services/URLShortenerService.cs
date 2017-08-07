using Google.Apis.Services;
using Google.Apis.Urlshortener.v1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Services
{
    public class URLShortenerService
    {
        UrlshortenerService service;
        public URLShortenerService() {
            service = new UrlshortenerService(new BaseClientService.Initializer()
            {
                ApiKey = "AIzaSyBiyJr0H5EgXPbPANyucxIedvrbG4XLYYE",
                ApplicationName = "CSCASSIGNMENT",
            });
        }

        public string shortenIt(string url)
        {
            var m = new Google.Apis.Urlshortener.v1.Data.Url();
            m.LongUrl = url;
            return service.Url.Insert(m).Execute().Id;
        }
    }
}
