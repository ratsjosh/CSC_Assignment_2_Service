using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using CSC_Assignment_2.Models;
using CSC_Assignment_2.Services;

namespace CSC_Assignment_2.Controllers
{
    //[Produces("application/json")]
    //[Route("api/Email")]
    public class EmailController : Controller
    {
        // POST: /api/Image/UploadProfilePic
        [HttpPost]
        //[ValidateAntiForgeryToken]
        public async Task<string> SendEmailAsync([FromBody]EmailObject emailModel)
        {
            EmailServices es = new EmailServices();
            var reply = await es.SendEmailAsync(emailModel.To, emailModel.Subject, emailModel.Body, emailModel.EmailType);
            return reply;
        }
    }
}