// Import required packages
const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");
const dotenv = require("dotenv");
const sgMail = require("@sendgrid/mail");
const winston = require("winston");
 
// Load environment variables from .env
dotenv.config();
 
// Configure logging with Winston
const logger = winston.createLogger({
  level: "debug", // Set to "debug" to capture detailed logs
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ timestamp, level, message }) => {
      return `${timestamp} - ${level.toUpperCase()}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: "email_service.log" }),
  ],
});
 
// Initialize AWS Secrets Manager client
const secretsClient = new SecretsManagerClient({
  region: process.env.AWS_REGION || "us-east-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});
 
// Function to fetch a secret from AWS Secrets Manager
async function getSecret(secretName) {
  logger.debug(`Fetching secret: ${secretName}`);
  try {
    const command = new GetSecretValueCommand({ SecretId: secretName });
    const response = await secretsClient.send(command);
 
    if (response.SecretString) {
      logger.debug(`Secret string received for: ${secretName}`);
      return JSON.parse(response.SecretString);
    } else {
      logger.debug(`Secret binary received for: ${secretName}`);
      const buff = Buffer.from(response.SecretBinary, "base64");
      return JSON.parse(buff.toString("ascii"));
    }
  } catch (error) {
    logger.error(`Error fetching secret ${secretName}: ${error}`);
    throw new Error(`Failed to fetch secret: ${error.message}`);
  }
}
 
// Load SendGrid API key
async function loadSendGridAPIKey() {
  try {
    if (process.env.NODE_ENV === "production") {
      logger.info(
        "Running in production environment. Fetching SendGrid API key from AWS Secrets Manager."
      );
      const secret = await getSecret("sendgrid-api-key");
      logger.debug(
        "SendGrid API key fetched successfully from Secrets Manager."
      );
 
      // Log partial key for debugging (only the first few characters for security)
      const sendGridAPIKey = secret.SENDGRID_API_KEY;
      if (sendGridAPIKey && sendGridAPIKey.startsWith("SG.")) {
        logger.debug(
          `SendGrid API Key (partial): ${sendGridAPIKey.slice(0, 4)}...`
        );
        return sendGridAPIKey;
      } else {
        logger.warn("Retrieved SendGrid API key does not start with 'SG.'.");
        throw new Error("Invalid SendGrid API key format.");
      }
    } else {
      logger.info(
        "Running in non-production environment. Using .env file for SendGrid API key."
      );
 
      const sendGridAPIKey = process.env.SENDGRID_API_KEY;
      if (sendGridAPIKey && sendGridAPIKey.startsWith("SG.")) {
        logger.debug(
          `SendGrid API Key (partial): ${sendGridAPIKey.slice(0, 4)}...`
        );
        return sendGridAPIKey;
      } else {
        logger.warn("SendGrid API key in .env does not start with 'SG.'.");
        throw new Error("Invalid SendGrid API key format in .env.");
      }
    }
  } catch (error) {
    logger.error(`Error loading SendGrid API key: ${error.message}`);
    throw error;
  }
}
 
// Handler function for email sending
exports.handler = async (event) => {
  logger.info("Handler triggered for email verification");
  logger.debug(`Event received: ${JSON.stringify(event, null, 2)}`);
 
  try {
    // Fetch SendGrid API key
    const sendGridAPIKey = await loadSendGridAPIKey();
    logger.info("Fetching SendGrid API key...");
    sgMail.setApiKey(sendGridAPIKey);
    logger.info("SendGrid API key set successfully.");
 
    for (const record of event.Records) {
      logger.debug(`Processing record: ${JSON.stringify(record, null, 2)}`);
      const snsMessage = JSON.parse(record.Sns.Message);
 
      // Validate SNS message fields
      if (
        !snsMessage.email ||
        !snsMessage.verificationToken ||
        !snsMessage.baseURL ||
        !snsMessage.verificationPath
      ) {
        logger.error("Invalid SNS message. Required fields are missing.");
        throw new Error(
          "Invalid SNS message. Required fields: email, verificationToken, baseURL, verificationPath."
        );
      }
 
      const email = snsMessage.email;
      const verificationToken = snsMessage.verificationToken;
      const baseURL = snsMessage.baseURL;
      const verificationPath = snsMessage.verificationPath;
 
      logger.info(`Received SNS message for email: ${email}`);
      logger.debug(`Verification token: ${verificationToken}`);
      logger.debug(`Base URL: ${baseURL}`);
      logger.debug(`Verification path: ${verificationPath}`);
 
      // Construct verification link
      const verificationLink = `${baseURL}${verificationPath}?token=${verificationToken}&email=${encodeURIComponent(
        email
      )}`;
      logger.info(`Verification link created: ${verificationLink}`);
 
      // Construct email message
      const msg = {
        to: email,
        from: `noreply@${new URL(baseURL).hostname}`,
        subject: "CSYE6225 Webapp - Verify Your Email",
        html: `<p>Dear User,<br>Please verify your email by <a href="${verificationLink}">clicking here</a>. This link expires in 2 minutes.<br><br>Thanks, <br>Your Team</p>`,
      };
 
      logger.debug(`Email message prepared: ${JSON.stringify(msg, null, 2)}`);
 
      try {
        const response = await sgMail.send(msg);
        logger.info(
          `Email sent to ${email} successfully. Response: ${JSON.stringify(
            response
          )}`
        );
      } catch (emailError) {
        logger.error(`Failed to send email to ${email}: ${emailError}`);
        throw emailError;
      }
    }
 
    logger.info("All emails processed successfully");
    return {
      statusCode: 200,
      body: "Verification email sent successfully",
    };
  } catch (error) {
    logger.error(`Error processing the verification emails: ${error}`);
    return {
      statusCode: 500,
      body: "An error occurred",
    };
  }
};