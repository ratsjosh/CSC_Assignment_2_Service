using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using static ServiceReferenceSMTP.SMTPSoapClient;

namespace CSC_Assignment_2.Services
{
    public class EmailServices
    {
        ServiceReferenceSMTP.SMTPSoapClient soap;
        ServiceReferenceSMTP.SendRequestBody requestBody;
        public EmailServices() {
        }

        public async Task<string> sendEmailAsync(string to, string subject, string body, EmailType type, string from = "talentsearchcustomerservice@gmail.com")
        {
            requestBody = new ServiceReferenceSMTP.SendRequestBody();
            requestBody.msgTo = to;
            requestBody.msgFrom = from;



            requestBody.msgBody = getTemplate(type, body);

            requestBody.msgSubject = subject;
            ServiceReferenceSMTP.SendRequest sendRequest = new ServiceReferenceSMTP.SendRequest(requestBody);

            soap = new ServiceReferenceSMTP.SMTPSoapClient(new EndpointConfiguration());

            var result = await soap.SendAsync(sendRequest);

            return result.Body.SendResult;
        }

        public string getTemplate(EmailType type, string msg) {

            switch (type) {

                case EmailType.Register:
                    return "<br><br>Thank you for registering with us!<br>Please click on the link below to verify your Talent Search account e-mail address:   " +
                     "<a href =\"" + msg + "\"><strong>Verify Account</strong></a>";
                    break;

                case EmailType.CustomerSupport:
                    return "<br><br>Thank you for contacting us with your enquiry of: " + msg +
                     "<br>We will try our best to get to your enquiry as soon as possible.";
                    break;
            }

            return "";
        }

        public enum EmailType {
            Register,
            CustomerSupport
        }
    }
}
