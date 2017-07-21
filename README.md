# TODO

- Client 

1. View photo Client (Web/mobile Application)
The view photo client allows users to view the photos.

2. Registration and Uploading of photo (Web/mobile Client)
	The registration client allows any users to register online.  In addition to registration, the Web Client allows registered users to upload photos to the cloud. 

NOTE: Every user stores the uploaded photo in his/her own BLOB

3. Change the status for the photo.
By default, the uploaded photo to Azure BLOB service is private. The status can be changed to PUBLIC only by the user who uploaded the photo.

Search the talents. This function is a paid service ($10 subscription fee for  life TIME) The yearly subscription is subject to change from time to time. Therefor you application needs to provide GUI for administrator to change accordingly.

- Server

Note: Web services should be hosted in seperate project(s) from web(mobile) apps.

The Cloud /Web Service for TLTT (The Life Time Talents )
Web Services serves as a middle tier between the clients and the database server.

The following are the major Web services:

1. Register Web Service
The Register Web Service allowed users to register and update their personal particular using Azure SQL service.

Additional features: GOOGLE sign up and Login

2. Email Web Service(SOAP)
The Email Web Service is to email the members the hyperlink for the registration or image uploaded. Refer to practical 5

3. Image Web Service
The Image Cloud Web Service will allow user to view and upload the photos using Azure BLOB service. Refer to practical 7 and practical  9

4. Captcha Web service
The Captcha web service is used to generate image containing characters. When a user is posting the question and answers, the web service is used to verify that the user is human.
Read more on http://en.wikipedia.org/wiki/Captcha

5. Talents web service to manage talents resources.
Supports CRUD operations. Secured using SSL and Token.
Model validation (Regular expression needs to be used)

6. Store session status in NOSQL (DynamoDB)

	To get started, please refer to Appendix D
