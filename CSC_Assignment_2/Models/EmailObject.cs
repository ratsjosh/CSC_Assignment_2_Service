using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static CSC_Assignment_2.Services.EmailServices;

namespace CSC_Assignment_2.Models
{
    public class EmailObject
    {
        public string To { get; set; }
        public string From { get; set; }
        public string Body { get; set; }
        public string Subject { get; set; }
        public EmailType EmailType { get; set; }

        public EmailObject() { }

        public EmailObject(string to, string from, string body, string subject, EmailType emailType) {
            this.To = to;
            this.Subject = subject;
            this.From = from;
            this.Body = body;
            this.EmailType = emailType;
        }


    }
}
