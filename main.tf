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
    from_port       = var.application_port
    to_port         = var.application_port
    protocol        = "tcp"
    security_groups = [aws_security_group.lb_security_group.id]
  }

  ingress {
    from_port   = 22
    to_port     = 22
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
  parameter {
    name         = "general_log"
    value        = "1"
    apply_method = "pending-reboot"
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
  identifier        = "csye6225"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"
  multi_az          = false
  db_name           = "csye6225"
  username          = "csye6225"
  # password            = var.db_password
  password = random_password.db_password.result
  # password            = jsondecode(data.aws_secretsmanager_secret_version.db_password_secret_version_data.secret_string).password
  db_subnet_group_name   = aws_db_subnet_group.private_subnets.name
  vpc_security_group_ids = [aws_security_group.db_security_group.id]
  parameter_group_name   = aws_db_parameter_group.my_db_parameter_group.name
  publicly_accessible    = false
  skip_final_snapshot    = true
  kms_key_id             = aws_kms_key.rds_kms_key.arn # Using RDS KMS Key // New Assignmnet 9
  storage_encrypted      = true                        # // New Assignmnet 9




  # apply_immediately = true # comment for chaitya

  tags = {
    Name = "csye6225-rds-instance"
  }
}

# Launch Template
resource "aws_launch_template" "app_launch_template" {
  name          = "web-app-launch-template"
  image_id      = var.custom_ami_id
  instance_type = var.instance_type
  # key_name      = var.aws_key_name

  iam_instance_profile {
    name = aws_iam_instance_profile.s3_access_profile.name
  }

  network_interfaces {
    security_groups             = [aws_security_group.app_security_group.id]
    associate_public_ip_address = true
  }
  # New Assignmnet 9

  # disable_api_termination = false # comment for chaitya

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      delete_on_termination = true
      volume_size           = 50
      volume_type           = "gp2"
      encrypted             = true
      kms_key_id            = aws_kms_key.ec2_kms_key.arn
    }
  }

  # lifecycle {
  #   create_before_destroy = true
  # }

  user_data = base64encode(<<EOF
#!/bin/bash

# Install MySQL client (if not already installed)
sudo apt update
sudo apt install -y mysql-client

# Set MySQL connection details
DB_HOST="${aws_db_instance.my_rds_instance.address}"
DB_ADMIN_USER="${var.db_user}"  # Replace with your admin username
DB_ADMIN_PASSWORD="${jsondecode(data.aws_secretsmanager_secret_version.db_password_secret_version_data.secret_string).password}"  # Replace with the admin password
DB_NAME="csye6225"
NEW_USER="csye6225"
NEW_PASSWORD="${jsondecode(data.aws_secretsmanager_secret_version.db_password_secret_version_data.secret_string).password}"


# Create a new user and grant full access
mysql -h "$DB_HOST" -u "$DB_ADMIN_USER" -p"$DB_ADMIN_PASSWORD" <<SQL
CREATE USER IF NOT EXISTS '$NEW_USER'@'%' IDENTIFIED BY '$NEW_PASSWORD';
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$NEW_USER'@'%';
FLUSH PRIVILEGES;
SQL

# Create the .env file with database environment variables
cat <<EOT >> /opt/.env
test = "${jsondecode(data.aws_secretsmanager_secret_version.db_password_secret_version_data.secret_string).password}"
MYSQL_HOST="$DB_HOST"
MYSQL_USER="$NEW_USER"
MYSQL_PASSWORD="$NEW_PASSWORD"
MYSQL_DATABASE="$DB_NAME"
PORT="5000"
AWS_REGION="${var.aws_region}"                          # AWS region variable
BUCKET_NAME="${aws_s3_bucket.my_bucket.id}"            # S3 Bucket name
SNS_TOPIC_ARN="${aws_sns_topic.email_notifications.arn}"  # Added SNS topic ARN

EOT

# Set permissions for the .env file to ensure it's accessible by the webapp user
sudo chown csye6225:csye6225 /opt/.env
sudo chmod 600 /opt/.env

sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config -m ec2 -c file:/opt/packer/cloudwatch-config.json -s

# Restart the web application and CloudWatch agent
sudo systemctl daemon-reload
sudo systemctl enable webapp.service
sudo systemctl start webapp.service

sudo systemctl restart webapp.service

EOF
  )

}

# Auto Scaling Group
resource "aws_autoscaling_group" "app_asg" {

  name             = "csye6225"
  # desired_capacity = 3
  # min_size         = 3
  # max_size         = 5
  desired_capacity    = 1
  min_size            = 1
  max_size            = 1
  vpc_zone_identifier = aws_subnet.public_subnets[*].id

  launch_template {
    id      = aws_launch_template.app_launch_template.id
    version = "$Latest"
  }
  target_group_arns         = [aws_lb_target_group.app_target_group.arn]
  health_check_type         = "EC2"
  health_check_grace_period = 300
  tag {
    key                 = "Name"
    value               = "AutoScalingGroup"
    propagate_at_launch = true
  }

  # wait_for_capacity_timeout = "0"
}


# Auto Scaling Policies
resource "aws_autoscaling_policy" "scale_up" {
  name                    = "scale_up_policy"
  scaling_adjustment      = 1
  adjustment_type         = "ChangeInCapacity"
  cooldown                = 60
  autoscaling_group_name  = aws_autoscaling_group.app_asg.name
  metric_aggregation_type = "Average"


}

# CloudWatch Alarms for Auto Scaling
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high_cpu_alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 12
  alarm_actions       = [aws_autoscaling_policy.scale_up.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }
}

resource "aws_autoscaling_policy" "scale_down" {
  name                    = "scale_down_policy"
  scaling_adjustment      = -1
  adjustment_type         = "ChangeInCapacity"
  cooldown                = 60
  autoscaling_group_name  = aws_autoscaling_group.app_asg.name
  metric_aggregation_type = "Average"
  # depends_on = [aws_autoscaling_group.app_asg]
}



resource "aws_cloudwatch_metric_alarm" "low_cpu" {
  alarm_name          = "low_cpu_alarm"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 8
  alarm_actions       = [aws_autoscaling_policy.scale_down.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.app_asg.name
  }
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
  bucket = aws_s3_bucket.my_bucket.bucket

  rule {
    id     = "expire-old-objects"
    status = "Enabled"
    filter {}
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
      # sse_algorithm = "AES256"
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_kms_key.arn # New Assignmnet 9
    }
  }
}

resource "aws_s3_bucket_public_access_block" "s3_bucket_public_access_block" {
  bucket = aws_s3_bucket.my_bucket.bucket

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
# Define IAM role for EC2 instance to access S3
resource "aws_iam_role" "s3_access_role" {
  name = "s3-access-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Sid = "RoleForEC2"
      },
    ]
  })
}

# IAM Policy for S3 Bucket Access (Allow EC2 to interact with S3)
resource "aws_iam_policy" "s3_access_policy" {
  name        = "s3-access-policy"
  description = "Policy to allow access to S3 Bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "kms:GenerateDataKey",
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:DescribeKey"
        ],
        Resource = "arn:aws:kms:us-east-1:${data.aws_caller_identity.current.account_id}:key/${aws_kms_key.s3_kms_key.key_id}"
        }, {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.my_bucket.arn,
          "${aws_s3_bucket.my_bucket.arn}/*"
        ]
      }
    ]
  })
}

# IAM Policy for CloudWatch Agent Access (Allow EC2 to push logs and metrics to CloudWatch)
resource "aws_iam_policy" "cloudwatch_agent_policy" {
  name        = "cloudwatch-agent-policy"
  description = "Policy to allow CloudWatch Agent to push logs and metrics"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
          "cloudwatch:ListMetrics",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:*"
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

# Attaching the S3 access policy to the IAM role
resource "aws_iam_policy_attachment" "s3_policy_attachment" {
  name       = "s3-policy-attachment"
  roles      = [aws_iam_role.s3_access_role.name]
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

# Attaching the CloudWatch agent policy to the IAM role
resource "aws_iam_policy_attachment" "cloudwatch_policy_attachment" {
  name       = "cloudwatch-policy-attachment"
  roles      = [aws_iam_role.s3_access_role.name]
  policy_arn = aws_iam_policy.cloudwatch_agent_policy.arn
}

# Create the IAM instance profile for EC2 to use this role
resource "aws_iam_instance_profile" "s3_access_profile" {
  name = "s3-access-profile"
  role = aws_iam_role.s3_access_role.name
}

# # Example EC2 instance that uses the IAM instance profile
# resource "aws_instance" "my_ec2_instance" {
#   ami             = var.custom_ami_id
#   instance_type   = var.instance_type
#   iam_instance_profile = aws_iam_instance_profile.s3_access_profile.name

#   tags = {
#     Name = "WebApp-Instance"
#   }
# }


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

  alias {
    name                   = aws_lb.app_load_balancer.dns_name
    zone_id                = aws_lb.app_load_balancer.zone_id
    evaluate_target_health = true
  }
  depends_on = [aws_lb.app_load_balancer]
  # tags = {
  #   Name        = "app-a-record"
  #   Environment = var.environment_tag
  # }
}

# Load Balancer Security Group
resource "aws_security_group" "lb_security_group" {
  vpc_id = aws_vpc.my_vpc.id
  name   = "load-balancer-security-group"

  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name        = "load-balancer-security-group"
    Environment = var.environment_tag
  }
}


# Application Load Balancer
resource "aws_lb" "app_load_balancer" {
  name               = "my-app-load-balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb_security_group.id]
  subnets            = [for subnet in aws_subnet.public_subnets : subnet.id]

  # enable_deletion_protection = false

  tags = {
    Name        = "app-load-balancer"
    Environment = var.environment_tag
  }
}

# IAM Role for Auto-Scaling Group
resource "aws_iam_role" "autoscaling_role" {
  name = "autoscaling-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "autoscaling.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}


# Target Group for Load Balancer
resource "aws_lb_target_group" "app_target_group" {
  name     = "app-target-group"
  port     = var.application_port
  protocol = "HTTP"
  vpc_id   = aws_vpc.my_vpc.id

  health_check {
    enabled             = true
    path                = "/healthz"
    port                = var.application_port
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 10
    unhealthy_threshold = 10
  }

  tags = {
    Name        = "app-target-group"
    Environment = var.environment_tag
  }
}
# new changes Assignment 9 
# Load Balancer Listener 

# comment for chaitya
# data "aws_acm_certificate" "issued" {
#   domain   = "${var.subdomain}.${var.domain_name}"
#   statuses = ["ISSUED"]
# }


resource "aws_lb_listener" "app_lb_listener" {
  load_balancer_arn = aws_lb.app_load_balancer.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  # certificate_arn   = data.aws_acm_certificate.issued.arn # comment for chaitya
  certificate_arn = var.certificate_arn
  # certificate_arn = "arn:aws:acm:us-east-1:396913738235:certificate/30162d3c-89b6-4717-8f2d-6448ae9fc02e"
  # certificate_arn = "arn:aws:acm:us-east-1:688567271402:certificate/60deb7f9-cd67-4b1b-bb3d-d20febeb09da"  #dev certificate
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app_target_group.arn
  }
}


# Output DB Endpoint
output "db_endpoint" {
  value = aws_db_instance.my_rds_instance.endpoint
}

# Output application URL
output "app_url" {
  value       = "http://${aws_route53_record.app_a_record.fqdn}:${var.application_port}/"
  description = "URL to access the application."
}



# SNS Topic for notifications
resource "aws_sns_topic" "email_notifications" {
  name = "email-notifications-topic"
  tags = {
    Name = "email-notifications-topic"
  }
}





# IAM Role for EC2 with SNS Publish Permissions

# Define the IAM Policy to allow EC2 to publish messages to the specified SNS topic
resource "aws_iam_policy" "ec2_sns_publish" {
  name = "ec2_sns_publish"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "sns:Publish",
        ]
        Effect   = "Allow"
        Resource = aws_sns_topic.email_notifications.arn
      },
    ]
  })
}

# Attach the above policy to the EC2 role
resource "aws_iam_policy_attachment" "ec2_sns_publish" {
  name       = "ec2_sns_publish"
  roles      = [aws_iam_role.s3_access_role.name]
  policy_arn = aws_iam_policy.ec2_sns_publish.arn
}


# IAM Role for Lambda
resource "aws_iam_role" "lambda_execution_role" {
  name = "lambda_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}

# IAM Policy for Lambda to access SNS, Secrets Manager, and database credentials
resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_policy"
  description = "Policy that allow Lambda function to access SNS, RDS, and CloudWatch."

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "sns:Publish",
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "rds:DescribeDBInstances",
          "rds:DescribeDBClusters",
          "rds:ListTagsForResource",
          "rds:DescribeDBClusterSnapshots",
          "rds:DescribeDBSnapshots",
          "rds-db:connect"
        ],
        Resource = "*"
      },
      {
        Effect   = "Allow",
        Action   = ["ses:SendEmail", "ses:SendRawEmail"],
        Resource = "*"
      }

    ]
  })
}

# Attach policy to Lambda execution role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# Lambda Function to handle SNS notifications
resource "aws_lambda_function" "email_notifications" {
  # filename         = "serverless.zip" # Replace with the path to your zipped project
  s3_bucket     = var.s3_bucket
  s3_key        = var.s3_key
  function_name = "sns-email-handler"
  role          = aws_iam_role.lambda_execution_role.arn
  handler       = "serverless/index.handler" # Update handler path as per your code structure
  # source_code_hash = filebase64sha256("serverless.zip")
  runtime = "nodejs20.x"




  environment {
    variables = {

      SENDGRID_API_KEY = var.sendgrid_api_key
      BASE_URL         = "demo.yashzaveri.me"
      SNS_TOPIC_ARN    = aws_sns_topic.email_notifications.arn
      # AWS_REGION    = var.aws_region

      # Add other environment variables from your .env if needed
    }
  }

}

# SNS Topic Subscription for Lambda
resource "aws_sns_topic_subscription" "lambda_sns_subscription" {
  topic_arn = aws_sns_topic.email_notifications.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.email_notifications.arn
}

# Grant Lambda permission to be invoked by SNS
resource "aws_lambda_permission" "allow_sns_invocation" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.email_notifications.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.email_notifications.arn
}
resource "aws_iam_policy" "lambda_s3_access_policy" {
  name = "LambdaS3AccessPolicy"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = "s3:GetObject",
        Resource = [for bucket in var.buckets : "arn:aws:s3:::${bucket}/*"]
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "lambda_s3_access_policy_attachment" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_s3_access_policy.arn
}



# ===================== New Part: AWS KMS Keys =====================
# KMS Key for EC2
resource "aws_kms_key" "ec2_kms_key" {
  description             = "KMS key for EC2"
  deletion_window_in_days = 7
  # customer_master_key_spec = "SYMMETRIC_DEFAULT" # comment for chaitya
  enable_key_rotation = true
  multi_region        = true

  policy = <<EOF
{
    "Id": "key-for-ebs",
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${var.user_account_id}:root"
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow access for Key Administrators",
            "Effect": "Allow",
            "Principal": {
               "AWS": "arn:aws:iam::${var.user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": [
                "kms:Create*",
                "kms:Describe*",
                "kms:Enable*",
                "kms:List*",
                "kms:Put*",
                "kms:Update*",
                "kms:Revoke*",
                "kms:Disable*",
                "kms:Get*",
                "kms:Delete*",
                "kms:TagResource",
                "kms:UntagResource",
                "kms:ScheduleKeyDeletion",
                "kms:CancelKeyDeletion"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow use of the key",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${var.user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow attachment of persistent resources",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${var.user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": [
                "kms:CreateGrant",
                "kms:ListGrants",
                "kms:RevokeGrant"
            ],
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }
        }
    ]
}
EOF

}

data "aws_caller_identity" "current" {}

#  alias for the Ec2 key
resource "aws_kms_alias" "alias_key_ebs" {
  name          = "alias/${var.alias_ec2_key}"
  target_key_id = aws_kms_key.ec2_kms_key.key_id
}


resource "aws_kms_key" "rds_kms_key" {
  description             = "KMS key for RDS"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  multi_region            = true
  policy = jsonencode(

    {
      "Id" : "key-for-rds",
      "Version" : "2012-10-17",
      "Statement" : [
        {
          "Sid" : "Enable IAM User Permissions",
          "Effect" : "Allow",
          "Principal" : {
            "AWS" : "arn:aws:iam::${var.user_account_id}:root"
          },
          "Action" : "kms:*",
          "Resource" : "*"
        },

        {
          "Sid" : "Allow access for Key Administrators",
          "Effect" : "Allow",
          "Principal" : {
            "AWS" : "arn:aws:iam::${var.user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          },
          "Action" : [
            "kms:Create*",
            "kms:Describe*",
            "kms:Enable*",
            "kms:List*",
            "kms:Put*",
            "kms:Update*",
            "kms:Revoke*",
            "kms:Disable*",
            "kms:Get*",
            "kms:Delete*",
            "kms:TagResource",
            "kms:UntagResource",
            "kms:ScheduleKeyDeletion",
            "kms:CancelKeyDeletion"
          ],
          "Resource" : "*"
        }
        ,
        {
          "Sid" : "Allow use of the key",
          "Effect" : "Allow",
          "Principal" : {
            "AWS" : "arn:aws:iam::${var.user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          },
          "Action" : [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:DescribeKey"
          ],
          "Resource" : "*"
        },
        {
          "Sid" : "Allow attachment of persistent resources",
          "Effect" : "Allow",
          "Principal" : {
            "AWS" : "arn:aws:iam::${var.user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
          },
          "Action" : [
            "kms:CreateGrant",
            "kms:ListGrants",
            "kms:RevokeGrant"
          ],
          "Resource" : "*",
          "Condition" : {
            "Bool" : {
              "kms:GrantIsForAWSResource" : "true"
            }
          }
        }
      ]
    }

  )
}

#  alias for the RDS volume
resource "aws_kms_alias" "alias_key_rds" {
  name          = "alias/${var.alias_rds_key}"
  target_key_id = aws_kms_key.rds_kms_key.id
}


# resource "aws_kms_alias" "rds_kms_key_alias" {
#   name          = "alias/RDSKey"
#   target_key_id = aws_kms_key.rds_kms_key.key_id
# }

resource "aws_kms_key" "s3_kms_key" {
  description             = "KMS_key_for_S3_bucket"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  multi_region            = true
}

resource "aws_kms_key_policy" "s3_kms_key_policy" {
  key_id = aws_kms_key.s3_kms_key.key_id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "Enable IAM User Permissions",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        "Action" : "kms:*",
        "Resource" : "*"
      },
      {
        "Sid" : "Allow access for Key Administrators",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        "Action" : [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow use of the key for S3",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      }
    ]
  })
}

resource "aws_kms_alias" "s3_kms_key_alias" {
  name          = "alias/S3Key"
  target_key_id = aws_kms_key.s3_kms_key.key_id
}

# KMS Key for Secret Manager
resource "aws_kms_key" "secret_manager_key" {
  description             = "KMS key for Secret Manager"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  multi_region            = true
}

resource "aws_kms_key_policy" "secret_manager_key_policy" {
  key_id = aws_kms_key.secret_manager_key.id
  policy = jsonencode({
    "Id" : "key-for-ebs",
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "Enable IAM User Permissions",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        },
        "Action" : "kms:*",
        "Resource" : "*"
      },
      {
        "Sid" : "Allow access for Key Administrators",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        "Action" : [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:Delete*",
          "kms:TagResource",
          "kms:UntagResource",
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "Allow use of the key",
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
        },
        "Action" : [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ],
        "Resource" : "*"
      }
    ]
  })
}


resource "aws_kms_alias" "secret_manager_key_alias" {
  name          = "alias/SecretManager"
  target_key_id = aws_kms_key.secret_manager_key.key_id
}

# ===================== New Part: AWS KMS Keys ===================== (end)


# ===================== Secrets Manager for Storing Database Password =====================
resource "aws_secretsmanager_secret" "db_password_secret" {
  name                    = "db-password"
  description             = "Database password for RDS"
  kms_key_id              = aws_kms_key.secret_manager_key.arn # Using Secrets Manager KMS Key
  recovery_window_in_days = 0

  tags = {
    Name = "db-password-secret"
  }
}

resource "random_password" "db_password" {
  length  = 16
  special = false
}

resource "aws_secretsmanager_secret_version" "db_password_secret_version" {
  secret_id = aws_secretsmanager_secret.db_password_secret.id
  secret_string = jsonencode({
    # username = "csye6225"
    # password = var.db_password
    password = random_password.db_password.result # Reference the generated password here
  })
}

# Data block to fetch the secret version (password) from Secrets Manager
data "aws_secretsmanager_secret_version" "db_password_secret_version_data" {
  secret_id  = aws_secretsmanager_secret.db_password_secret.id
  depends_on = [aws_secretsmanager_secret_version.db_password_secret_version]
}

# Accessing the password from the data block
output "db_password_from_secrets_manager" {
  value     = jsondecode(data.aws_secretsmanager_secret_version.db_password_secret_version_data.secret_string).password
  sensitive = true
}

# ===================== Secrets Manager for Storing Database Password =====================(end)

# ===================== Email Service Credentials in Secrets Manager =====================
resource "aws_secretsmanager_secret" "email_service_secret" {
  name                    = "email-service-credentials"
  description             = "Credentials for Email Service"
  kms_key_id              = aws_kms_key.secret_manager_key.arn # Using Secrets Manager KMS Key
  recovery_window_in_days = 0

  tags = {
    Name = "email-service-secret"
  }
}

resource "aws_secretsmanager_secret_version" "email_service_secret_version" {
  secret_id = aws_secretsmanager_secret.email_service_secret.id
  secret_string = jsonencode({
    SENDGRID_API_KEY = var.sendgrid_api_key
  })
}

# ===================== Email Service Credentials in Secrets Manager ===================== (end)

# Lambda function retrieves email service credentials dynamically (update Lambda code to use Secrets Manager).

# ===================== Load Balancer SSL Certificate =====================
# resource "aws_acm_certificate" "dev_ssl_certificate" {
#   domain_name       = "${var.subdomain}.${var.domain_name}"
#   validation_method = "DNS"

#   tags = {
#     Name = "dev-ssl-certificate"
#   }
# }

# resource "aws_acm_certificate_validation" "dev_ssl_certificate_validation" {
#   certificate_arn         = aws_acm_certificate.dev_ssl_certificate.arn
#   validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
# }

# ===================== Load Balancer SSL Certificate =====================(end)

# Lambda IAM Role Permissions to Access Secrets Manager
resource "aws_iam_policy" "lambda_secrets_access" {
  name        = "LambdaSecretsAccessPolicy"
  description = "Policy for Lambda to access Secrets Manager"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        # Effect = "Allow"
        # Action = [
        #   "secretsmanager:GetSecretValue",
        #   "secretsmanager:DescribeSecret"
        # ],
        # Resource = [
        #   aws_secretsmanager_secret.email_service_secret.arn,
        #   # aws_secretsmanager_secret.domain.arn
        # ]
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:ListSecrets"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow",
        Action   = "kms:Decrypt",
        Resource = "*"
      }
    ]
  })
}

# Attach Secrets Manager Policy to Lambda Execution Role
resource "aws_iam_role_policy_attachment" "attach_lambda_secrets_access" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_secrets_access.arn
}


resource "aws_iam_policy" "secrets_access" {
  name        = "SecretsAccessPolicy"
  description = "Policy to access Secrets Manager"
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ],
       Resource = "*"
      },
      {
        Effect   = "Allow",
        Action   = "kms:Decrypt",
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_ec2_secret_manager" {
  role       = aws_iam_role.s3_access_role.name
  policy_arn = aws_iam_policy.secrets_access.arn
}





