using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using CSC_Assignment_2.Services;

namespace CSC_Assignment_2.Controllers
{
    [Authorize]
    [Produces("application/json")]
    [Route("api/Image")]
    public class ImageController : Controller
    {
        // POST: /api/Image/UploadProfilePic
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<string> UploadProfilePic()
        {
            BlobServices blobService = new BlobServices();
            await blobService.GetAllImageFromContainerAsync("");

            return "";
        }

        // POST: /api/Image/UploadMultiplePic
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<string> UploadMultiplePic()
        {
            BlobServices blobService = new BlobServices();
            await blobService.GetAllImageFromContainerAsync("");

            return "";
        }

        // GET: /api/Image/GetAllImage
        [HttpGet]
        [ValidateAntiForgeryToken]
        public async Task<string> GetAllImage()
        {
            BlobServices blobService = new BlobServices();
            await blobService.GetAllImageFromContainerAsync("");

            return "";
        }
    }
}