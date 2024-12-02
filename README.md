# tf-aws-infra

##Assignment A09



## SSL Certificate Import for Demo Environment

To import an SSL certificate for the demo environment, follow these steps:

1. Obtain the certificate from your SSL vendor. Ensure you have the `.crt` file (certificate), `.key` file (private key), and the `.crt` CA bundle.
2. Run the following command to import the certificate into AWS Certificate Manager:

   ```bash
sudo aws acm import-certificate --certificate fileb://path/to/certificate.crt \
     --private-key fileb://path/to/private.key \
     --certificate-chain fileb://path/to/ca_bundle.crt \
     --region <your-region>
    --profile <your-profile>

