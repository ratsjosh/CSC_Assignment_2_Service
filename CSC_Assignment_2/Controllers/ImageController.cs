using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using CSC_Assignment_2.Services;
using CSC_Assignment_2.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace CSC_Assignment_2.Controllers
{
    //[Authorize]
    //[Produces("application/json")]
    [Authorize(ActiveAuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class ImageController : Controller
    {
        // POST: /api/Image/UploadProfilePic
        [HttpPost]
        //[ValidateAntiForgeryToken]
        public async Task<string> UploadProfilePicAsync([FromBody]ImageModel imageModel)
        {
            BlobServices blobService = new BlobServices();
            return await blobService.UploadImageToBlobStorageAsync(Convert.FromBase64String(imageModel.base64), imageModel.userId);
        }

        //// POST: /api/Image/UploadMultiplePic
        //[HttpPost]
        //public async Task<List<string>> UploadMultiplePicAsync(ImageModel imageModel)
        //{
        //    BlobServices blobService = new BlobServices();
        //    List<string> uploadedUri = new List<string>();

        //    foreach (var image in imageModel.ListOfBase64) {
        //        uploadedUri.Add(await blobService.UploadImageToBlobStorageAsync(Convert.FromBase64String(image), imageModel.userId));
        //    }
        //    return uploadedUri;

        //}

        // GET: /api/Image/GetAllImage
        [HttpGet]
        //[ValidateAntiForgeryToken]
        public async Task<List<string>> GetAllImage()
        {
            string userId = Request.Query["userId"];
            BlobServices blobService = new BlobServices();
           
            return await blobService.GetAllImageFromContainerAsync(userId);
        }
    }
}