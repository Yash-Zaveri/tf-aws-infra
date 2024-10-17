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

# EC2 Instance
variable "instance_type" {
  default     = "t2.micro"
  description = "Instance type for EC2"
}


variable "application_port" {
  type        = number
  description = "Port for application"
  default     = 8080 # Change to the port your application uses
}

variable "custom_ami_id" {
  description = "The ID of the custom AMI to be used for the EC2 instance"
  type        = string
}
