using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Services
{


    public class BlobServices
    {
        private CloudStorageAccount account { get; set; }
        private CloudBlobClient client { get; set; }

        public BlobServices() {
            var creds = new StorageCredentials(ApplicationSettings.GetString("BlobAccountName"), ApplicationSettings.GetString("BlobKey"));
            client = new CloudStorageAccount(creds, true).CreateCloudBlobClient();
            client.DefaultRequestOptions.ParallelOperationThreadCount = Environment.ProcessorCount;
        }

        public string UploadImageToBlobStorage(Byte[] imageByte, string containerName)
        {
            CloudBlobContainer c = client.GetContainerReference(containerName);
            c.SetPermissionsAsync(new BlobContainerPermissions { PublicAccess = BlobContainerPublicAccessType.Off });
            c.CreateIfNotExistsAsync();

            ICloudBlob blob = c.GetBlockBlobReference(Guid.NewGuid().ToString());
            blob.StreamWriteSizeInBytes = 1048576;
            blob.UploadFromByteArrayAsync(imageByte, 0, imageByte.Length);
            return blob.Uri.AbsoluteUri;
        }

        public async Task<List<Uri>> GetAllImageFromContainerAsync(string containerName) {

            BlobContinuationToken continuationToken = null;

            CloudBlobContainer container = client.GetContainerReference(containerName);

            List<IListBlobItem> blobResults = new List<IListBlobItem>();
            List<Uri> urlResults = new List<Uri>();
            do
            {
                var response = await container.ListBlobsSegmentedAsync(continuationToken);
                continuationToken = response.ContinuationToken;
                blobResults = response.Results.ToList<IListBlobItem>();

                foreach (IListBlobItem blob in blobResults) {
                    urlResults.Add(blob.Uri);
                }

                return urlResults;
            }
            while (continuationToken != null);
        }
    }


}
