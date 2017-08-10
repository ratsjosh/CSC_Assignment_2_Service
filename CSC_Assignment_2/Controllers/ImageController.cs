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
using System.IO;
using Microsoft.Extensions.Configuration;
using Microsoft.WindowsAzure.Storage.Blob;

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
        public async Task<string> UploadPictureAsync([FromBody]ImageModel imageModel)
        {
            BlobServices blobService = new BlobServices();
            return await blobService.UploadImageToBlobStorageAsync(Convert.FromBase64String(imageModel.ImageBase64), imageModel.Id);
        }

        // POST: /api/Image/UploadMultiplePic
        [HttpPost]
        public async Task<IActionResult> UploadMultiplePicAsync(IFormFile file)
        {
            bool isSavedSuccessfully = false;
            string id = Request.Headers["UserId"];
            string url = "";
            string sasKey = Startup.Configuration.GetConnectionString("BlobSASkey");
            string error = "";
            if (id != null)
            {
                try
                {
                    BlobServices blobService = new BlobServices();

                    //foreach (var file in files)
                    //{

                    //Save file content goes here
                    if (file != null && file.Length > 0)
                    {

                        using (var fileStream = file.OpenReadStream())
                        using (var ms = new MemoryStream())
                        {
                            fileStream.CopyTo(ms);
                            var fileBytes = ms.ToArray();
                            url = await blobService.UploadImageToBlobStorageAsync(fileBytes, id);
                            isSavedSuccessfully = true;
                        }
                    }



                }
                catch (Exception ex)
                {
                    error = ex.ToString();
                    isSavedSuccessfully = false;
                }
            }

            if (isSavedSuccessfully)
                {
                    return Json(new { ImageURL = url + sasKey });
                }
                else
                {
                    return Json(new { Message = error });
                }
            
            //BlobServices blobService = new BlobServices();
            //List<string> uploadedUri = new List<string>();

            //foreach (var image in imageModel.ListOfBase64)
            //{
            //    uploadedUri.Add(await blobService.UploadImageToBlobStorageAsync(Convert.FromBase64String(image), imageModel.Id));
            //}
            //return uploadedUri;
        }

        // GET: /api/Image/GetAllImage
        [HttpPut]
        //[ValidateAntiForgeryToken]
        public async Task<bool> ChangeStorage(string userId, bool state)
        {
            BlobServices blobService = new BlobServices();
            var s = BlobContainerPublicAccessType.Blob;
            if (!state) {
                s = BlobContainerPublicAccessType.Container;
            }

            return await blobService.changeContainerState(userId, s);
        }

        // GET: /api/Image/GetAllImage
        [HttpGet]
        //[ValidateAntiForgeryToken]
        public async Task<BlobContainerPublicAccessType> GetStorageState(string userId)
        {
            BlobServices blobService = new BlobServices();

            return await blobService.getContainerState(userId);
        }

        // GET: /api/Image/GetAllImage
        [HttpGet]
        //[ValidateAntiForgeryToken]
        public async Task<List<string>> GetAllImage()
        {
            string userId = Request.Query["userId"];
            BlobServices blobService = new BlobServices();
            return await blobService.GetAllImageFromContainerAsync(userId);


        }

        [HttpGet]
        //[ValidateAntiForgeryToken]
        public async Task<List<string>> GetAllImageSingleUser()
        {
            string userId = Request.Query["userId"];
            BlobServices blobService = new BlobServices();

            if (await blobService.getContainerState(userId) == BlobContainerPublicAccessType.Container)
            {
                return await blobService.GetAllImageFromContainerAsync(userId);
            }
            else
            {
                return null;
            }

        }
    }
}