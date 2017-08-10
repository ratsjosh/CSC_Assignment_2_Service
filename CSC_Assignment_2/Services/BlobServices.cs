using Microsoft.Extensions.Configuration;
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
            string BlobAccountName = Startup.Configuration.GetConnectionString("BlobAccountName");
            string BlobKey = Startup.Configuration.GetConnectionString("BlobKey");
            var creds = new StorageCredentials(BlobAccountName, BlobKey);
            client = new CloudStorageAccount(creds, true).CreateCloudBlobClient();
            client.DefaultRequestOptions.ParallelOperationThreadCount = Environment.ProcessorCount;
        }

        public async Task<string> UploadImageToBlobStorageAsync(Byte[] imageByte, string containerName)
        {
            CloudBlobContainer c = client.GetContainerReference(containerName);
            await c.CreateIfNotExistsAsync();
            await c.SetPermissionsAsync(new BlobContainerPermissions { PublicAccess = BlobContainerPublicAccessType.Blob });

            ICloudBlob blob = c.GetBlockBlobReference(Guid.NewGuid().ToString());
            blob.StreamWriteSizeInBytes = 1048576;
            await blob.UploadFromByteArrayAsync(imageByte, 0, imageByte.Length);
            return blob.Uri.AbsoluteUri;
        }

        public async Task<bool> changeContainerState(string containerName, BlobContainerPublicAccessType type) {
            try
            {
                CloudBlobContainer c = client.GetContainerReference(containerName);
                await c.SetPermissionsAsync(new BlobContainerPermissions { PublicAccess = type });

                return true;
            }
            catch (Exception e) {
                return false;
            }
        }

        public async Task<BlobContainerPublicAccessType> getContainerState(string containerName)
        {
            try
            {
                CloudBlobContainer c = client.GetContainerReference(containerName);

                return (await c.GetPermissionsAsync()).PublicAccess;
            }
            catch (Exception e)
            {
                return BlobContainerPublicAccessType.Unknown;
            }
        }

        public async Task<string> DeleteImageFromBlobStorageAsync(Byte[] imageByte, string containerName)
        {
            CloudBlobContainer c = client.GetContainerReference(containerName);
            await c.CreateIfNotExistsAsync();
            await c.SetPermissionsAsync(new BlobContainerPermissions { PublicAccess = BlobContainerPublicAccessType.Blob });

            ICloudBlob blob = c.GetBlockBlobReference(Guid.NewGuid().ToString());
            blob.StreamWriteSizeInBytes = 1048576;
            await blob.UploadFromByteArrayAsync(imageByte, 0, imageByte.Length);
            return blob.Uri.AbsoluteUri;
        }

        public async Task<List<string>> GetAllImageFromContainerAsync(string containerName) {

            BlobContinuationToken continuationToken = null;

            CloudBlobContainer container = client.GetContainerReference(containerName);

            List<IListBlobItem> blobResults = new List<IListBlobItem>();
            List<string> urlResults = new List<string>();
            string sasKey = Startup.Configuration.GetConnectionString("BlobSASkey");
            do
            {
                var response = await container.ListBlobsSegmentedAsync(continuationToken);
                continuationToken = response.ContinuationToken;
                blobResults = response.Results.ToList<IListBlobItem>();

                foreach (IListBlobItem blob in blobResults) {
                    urlResults.Add(blob.Uri.AbsoluteUri + sasKey);
                }

                return urlResults;
            }
            while (continuationToken != null);
        }
    }


}
