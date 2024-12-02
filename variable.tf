# Existing variables
variable "aws_profile" {
  description = "AWS CLI profile to use"
}

variable "aws_region" {
  default     = "us-east-1"
  description = "AWS Region"
}

variable "vpc_cidr" {
  default     = "10.0.0.0/16"
  description = "VPC CIDR block"
}

variable "availability_zones" {
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
  description = "List of availability zones"
}

variable "instance_type" {
  default     = "t2.micro"
  description = "Instance type for EC2"
}

variable "application_port" {
  type        = number
  default     = 5000 # Change to the port your application uses
  description = "Port for application"
}

variable "custom_ami_id" {
  type        = string
  description = "The ID of the custom AMI to be used for the EC2 instance"
}

variable "key_name" {
  description = "Key pair to be used for SSH access to EC2 instances"
  default     = null
}

variable "root_volume_size" {
  type        = number
  default     = 25
  description = "The size of the root volume for the EC2 instance"
}

variable "db_user" {
  type        = string
  default     = ""
  description = "Database username."
}

variable "db_password" {
  type        = string
  default     = ""
  description = "Database password."
}

variable "db_name" {
  type        = string
  default     = ""
  description = "Database name."
}

variable "db_port" {
  type        = number
  default     = 3306
  description = "Database port."
}

# New variables added for IAM, S3, and tagging configurations
variable "environment_tag" {
  type        = string
  default     = "production"
  description = "Environment tag for resources (e.g., production, staging, development)"
}

variable "s3_bucket_name_prefix" {
  type        = string
  description = "Prefix for the S3 bucket name to ensure uniqueness"
  default     = "my-app-bucket"
}

variable "domain_name" {
  type        = string
  description = "Domain name for Route 53 configuration"
}

variable "subdomain" {
  type        = string
  description = "Subdomain to use for the application Route 53 A record"
  default     = "app"
}

variable "s3_bucket_name" {
  description = "The name of the S3 bucket"
  type        = string
}

variable "record_type" {
  description = "The type of the DNS record"
  type        = string
  default     = "A" # You can change this default value if needed
}

variable "ttl" {
  description = "Time to live for the DNS record in seconds"
  type        = number
  default     = 60 # Default TTL value
}

variable "sendgrid_api_key" {
  description = "SendGrid API key for sending emails"
  type        = string
  sensitive   = true
}


variable "s3_bucket" {
  description = "S3 Bucket Name For Email Zip"
  type        = string
}

variable "s3_key" {
  description = "Bucket Key Name Having Email Zip"
  type        = string
}



variable "buckets" {
  description = "bucket"
  type        = list(string)

}
variable "user_account_id" {
  description = "account id"
  type        = string
  default     = "396913738235"
}
variable "alias_ec2_key" {
  description = "alias for ebs key"
  type        = string
  default     = "xxxx"
}
variable "alias_rds_key" {
  description = "alias for rds key"
  type        = string
  default     = "xxxx"
}

variable "certificate_arn" {
  description = "certificate_arn"
  type        = string
  default     = "xxxx"
}
