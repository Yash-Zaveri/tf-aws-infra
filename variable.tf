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
  description = "Database port number."
}

variable "environment_tag" {
  type        = string
  default     = ""
  description = "Environment tag for resources."
}
