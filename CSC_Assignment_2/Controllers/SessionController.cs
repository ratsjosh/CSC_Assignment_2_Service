using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Amazon.Runtime;
using Amazon.DynamoDBv2;
using Microsoft.Extensions.Configuration;
using Amazon.DynamoDBv2.Model;
using System.Threading;
using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;
using CSC_Assignment_2.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;

namespace CSC_Assignment_2.Controllers
{

    [Authorize(ActiveAuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class SessionController : Controller
    {
        private BasicAWSCredentials _credentials;
        private AmazonDynamoDBClient _client;
        private readonly IConfiguration _configuration;
        private DynamoDBContext _context;

        public SessionController(
            IConfiguration configuration)
        {
            _configuration = configuration;
            string accessKey = _configuration.GetConnectionString("DynamoDb:AccessKey");
            string secretKey = _configuration.GetConnectionString("DynamoDb:SecretKey");
            _credentials = new BasicAWSCredentials(accessKey, secretKey);
            _client = new AmazonDynamoDBClient(_credentials, Amazon.RegionEndpoint.USWest2);
            // Verify if table has been generated
            Task.Run(() => VerifyTableAsync("Talents")).Wait();
        }

        public async Task VerifyTableAsync(string tableName)
        {
            var tableResponse = await _client.ListTablesAsync();
            if (!tableResponse.TableNames.Contains(tableName))
            {
                await _client.CreateTableAsync(new CreateTableRequest
                {
                    TableName = tableName,
                    ProvisionedThroughput = new ProvisionedThroughput
                    {
                        ReadCapacityUnits = 3,
                        WriteCapacityUnits = 1
                    },
                    KeySchema = new List<KeySchemaElement>
                    {
                        new KeySchemaElement
                        {
                            AttributeName = "AccessToken",
                            KeyType = KeyType.HASH
                        }
                    },
                    AttributeDefinitions = new List<AttributeDefinition>
                    {
                        new AttributeDefinition {
                            AttributeName = "AccessToken",
                            AttributeType =ScalarAttributeType.S
                        }
                    }
                });
                bool isTableAvailable = false;
                while (!isTableAvailable)
                {
                    Thread.Sleep(1000);
                    var tableStatus = await _client.DescribeTableAsync(tableName);
                    isTableAvailable = tableStatus.Table.TableStatus == "ACTIVE";
                }
            }
            _context = new DynamoDBContext(_client);
        }

        // GET: api/Session/GetAll
        /// <summary>
        /// Get user by the access token
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        [HttpGet]
        public async Task<LoginModel> GetUserByAccessTokenAsync()
        {
            string accessToken = Request.Headers["AccessToken"];
            if (!string.IsNullOrEmpty(accessToken))
            {
                List<ScanCondition> conditions = new List<ScanCondition>();
                conditions.Add(new ScanCondition("AccessToken", ScanOperator.Equal, accessToken));
                List<LoginModel> result = await _context.ScanAsync<LoginModel>(conditions).GetRemainingAsync();
                return result.FirstOrDefault();
            }
            else
            {
                return null;
            }
        }

        // POST: api/Session
        [HttpPost]
        public async Task<IActionResult> PostAsync([FromBody]LoginModel model)
        {
            if (ModelState.IsValid)
            {
                await _context.SaveAsync(model);
                return Ok();
            }
            else
            {
                return BadRequest(ModelState);
            }
        }

        // DELETE: api/ApiWithActions/5
        [HttpDelete("{id}")]
        public void Delete(int id)
        {
        }
    }
}
