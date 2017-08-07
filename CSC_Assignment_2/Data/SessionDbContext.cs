using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.Model;
using Amazon.Runtime;
using CSC_Assignment_2.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace CSC_Assignment_2.Data
{
    public class SessionDbContext
    {
        private BasicAWSCredentials _credentials;
        public AmazonDynamoDBClient _client;
        public DynamoDBContext _context;
        private readonly IConfiguration _configuration;

        public SessionDbContext(IConfiguration configuration)
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

        public async void PostAsync(LoginModel model)
        {
            await _context.SaveAsync(model);
        }
    }
}
