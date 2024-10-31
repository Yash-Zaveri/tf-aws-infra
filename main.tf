provider "aws" {
  profile = var.aws_profile
  region  = var.aws_region
}

# VPC creation
resource "aws_vpc" "my_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "my-vpc"
  }
}

# Public Subnets
resource "aws_subnet" "public_subnets" {
  count                   = 3
  vpc_id                  = aws_vpc.my_vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 3, count.index)
  map_public_ip_on_launch = true
  availability_zone       = element(var.availability_zones, count.index)
  tags = {
    Name = "public-subnet-${count.index + 1}"
  }
}

# Private Subnets
resource "aws_subnet" "private_subnets" {
  count             = 3
  vpc_id            = aws_vpc.my_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 3, count.index + 3)
  availability_zone = element(var.availability_zones, count.index)
  tags = {
    Name = "private-subnet-${count.index + 1}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.my_vpc.id
  tags = {
    Name = "my-internet-gateway"
  }
}

# Public Route Table
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.my_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "my-public-route-table"
  }
}

# Associate public subnets with public route table
resource "aws_route_table_association" "public_associations" {
  count          = length(aws_subnet.public_subnets)
  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public_route_table.id
}

# Private Route Table (without NAT)
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.my_vpc.id
  tags = {
    Name = "my-private-route-table"
  }
}

# Associate private subnets with private route table
resource "aws_route_table_association" "private_associations" {
  count          = length(aws_subnet.private_subnets)
  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private_route_table.id
}

# Application Security Group
resource "aws_security_group" "app_security_group" {
  vpc_id = aws_vpc.my_vpc.id
  name   = "app-security-group"

  ingress {
    from_port   = var.application_port
    to_port     = var.application_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "app-security-group"
    Environment = var.environment_tag
  }
}

# Database Security Group
resource "aws_security_group" "db_security_group" {
  vpc_id = aws_vpc.my_vpc.id
  name   = "db-security-group"

  ingress {
    from_port       = var.db_port
    to_port         = var.db_port
    protocol        = "tcp"
    security_groups = [aws_security_group.app_security_group.id]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "db-security-group"
    Environment = var.environment_tag
  }
}

# RDS Parameter Group (MySQL)
resource "aws_db_parameter_group" "my_db_parameter_group" {
  name        = "my-db-param-group"
  family      = "mysql8.0"
  description = "MySQL 8.0 parameter group"

  parameter {
    name  = "max_connections"
    value = "100"
  }

  tags = {
    Name = "my-db-param-group"
  }
}

# RDS Subnet Group (Private Subnets)
resource "aws_db_subnet_group" "private_subnets" {
  name       = "my-db-subnet-group"
  subnet_ids = [for subnet in aws_subnet.private_subnets : subnet.id]

  tags = {
    Name = "my-db-subnet-group"
  }
}

# RDS Instance (MySQL)
resource "aws_db_instance" "my_rds_instance" {
  identifier             = "csye6225"
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  db_name                = "csye6225"
  username               = "csye6225"
  password               = var.db_password
  multi_az               = false
  publicly_accessible    = false
  vpc_security_group_ids = [aws_security_group.db_security_group.id]
  db_subnet_group_name   = aws_db_subnet_group.private_subnets.name
  parameter_group_name   = aws_db_parameter_group.my_db_parameter_group.name
  skip_final_snapshot    = true

  tags = {
    Name = "csye6225-rds-instance"
  }
}

# EC2 Instance with User Data to auto-configure DB connection
resource "aws_instance" "app_instance" {
  ami                    = var.custom_ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public_subnets[0].id
  vpc_security_group_ids = [aws_security_group.app_security_group.id]
  iam_instance_profile   = aws_iam_instance_profile.s3_access_profile.name



  root_block_device {
    volume_type           = "gp2"
    volume_size           = var.root_volume_size
    delete_on_termination = true
  }

  disable_api_termination = false

  user_data = base64encode(<<EOF
#!/bin/bash


# Create the .env file with database environment variables
cat <<EOT >> /opt/.env
MYSQL_HOST="${aws_db_instance.my_rds_instance.address}"
MYSQL_USER="csye6225"
MYSQL_PASSWORD="${var.db_password}"
MYSQL_DATABASE="csye6225"
PORT="5000"
AWS_REGION="${var.aws_region}"                          # AWS region variable
BUCKET_NAME="${aws_s3_bucket.my_bucket.id}"            # S3 Bucket name

EOT

# Set permissions for the .env file to ensure it's accessible by the webapp user
sudo chown csye6225:csye6225 /opt/.env
sudo chmod 600 /opt/.env

sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config -m ec2 -c file:/opt/packer/cloudwatch-config.json -s

# Restart the web application and CloudWatch agent
sudo systemctl daemon-reload
sudo systemctl restart webapp.service

EOF
  )

  tags = {
    Name = "app-instance"
  }
}

# Output DB Endpoint
output "db_endpoint" {
  value = aws_db_instance.my_rds_instance.endpoint
}

# S3 Bucket and IAM Role/Policy

resource "random_id" "bucket_name" {
  byte_length = 7
}

resource "aws_s3_bucket" "my_bucket" {
  bucket = "my-app-bucket-${random_id.bucket_name.hex}"




  force_destroy = true # Allow bucket deletion even if not empty

  tags = {
    Name        = "my-app-bucket"
    Environment = var.environment_tag
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "my_bucket_lifecycle" {
  bucket = aws_s3_bucket.my_bucket.id

  rule {
    id     = "expire-old-objects"
    status = "Enabled"

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = 365 # Adjust this if needed
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "my_bucket_encryption" {
  bucket = aws_s3_bucket.my_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
# Define IAM role for EC2 instance to access S3
resource "aws_iam_role" "s3_access_role" {
  name = "s3-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
}

# Attach policy to IAM role
resource "aws_iam_role_policy" "s3_access_policy" {
  name = "s3-access-policy"
  role = aws_iam_role.s3_access_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject"
        ]
        Effect = "Allow"
        Resource = [
          aws_s3_bucket.my_bucket.arn,
          "${aws_s3_bucket.my_bucket.arn}/*"
        ]
      }
    ]
  })
}

# Define policy for CloudWatch Agent
resource "aws_iam_role_policy" "cloudwatch_agent_policy" {
  name = "cloudwatch-agent-policy"
  role = aws_iam_role.s3_access_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "ec2:DescribeVolumes",
          "ec2:DescribeTags",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams",
          "logs:DescribeLogGroups",
          "logs:CreateLogStream",
          "logs:CreateLogGroup"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter"
        ]
        Resource = "arn:aws:ssm:*:*:parameter/AmazonCloudWatch-*"
      }
    ]
  })
}

# Associate the IAM role with EC2 instance profile
resource "aws_iam_instance_profile" "s3_access_profile" {
  name = "s3-access-profile"
  role = aws_iam_role.s3_access_role.name
}

# Route 53 Zone for Domain (retrieve existing zone)
data "aws_route53_zone" "selected_zone" {
  name         = "${var.subdomain}.${var.domain_name}"
  private_zone = false
}

# Route 53 A Record for EC2 instance
resource "aws_route53_record" "app_a_record" {
  zone_id = data.aws_route53_zone.selected_zone.zone_id
  name    = "${var.subdomain}.${var.domain_name}"
  type    = var.record_type # Use the variable for record type
  ttl     = var.ttl         # Use the variable for TTL
  records = [aws_instance.app_instance.public_ip]

  depends_on = [aws_instance.app_instance]

  # tags = {
  #   Name        = "app-a-record"
  #   Environment = var.environment_tag
  # }
}

# Output application URL
output "app_url" {
  value       = "http://${aws_route53_record.app_a_record.fqdn}:${var.application_port}/"
  description = "URL to access the application."
}
