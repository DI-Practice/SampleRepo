provider "aws" {
  region     = var.aws_region
}

#-------------------------------------------Network Creation--------------------------------------------
#Vpc Creation
resource "aws_vpc" "TF_Vpc" {
  cidr_block       = var.vpc_cidr
  enable_dns_hostnames  = true
  instance_tenancy = "default"
  tags = {
    Name = "Vpc"
  }
}

#PublicSubnet1 Creation
resource "aws_subnet" "PublicSubnet1" {
  vpc_id     = "${aws_vpc.TF_Vpc.id}"
  cidr_block = var.PublicSubnet1_cidr
  availability_zone = var.AZ1
  map_public_ip_on_launch = true

   tags = {
       Name = "PublicSubnet1"
   }
}

#PublicSubnet2 Creation
resource "aws_subnet" "PublicSubnet2" {
  vpc_id     = "${aws_vpc.TF_Vpc.id}"
  cidr_block = var.PublicSubnet2_cidr
  availability_zone = var.AZ2
  map_public_ip_on_launch = true
  tags = {
       Name = "PublicSubnet2"
   }
}

#PrivateSubnet Creation
resource "aws_subnet" "PrivateSubnet" {
  vpc_id     = "${aws_vpc.TF_Vpc.id}"
  cidr_block = var.PrivateSubnet_cidr
  availability_zone =  var.AZ1
  tags = {
       Name = "PrivateSubnet"
   }
}

#EIP Creation
resource "aws_eip" "eip" {
  vpc = true
}

#NAT gateway in PublicSubnet1 
resource "aws_nat_gateway" "nat" {
  allocation_id = "${aws_eip.eip.id}"
  subnet_id     = "${aws_subnet.PublicSubnet1.id}"
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "NAT"
  }
}

#IGW Creation
resource "aws_internet_gateway" "igw" {
  vpc_id = "${aws_vpc.TF_Vpc.id}"

  tags = {
    Name = "IGW"
  }
}

#PublicRouteTable Creation
resource "aws_route_table" "PublicRouteTable" {
  vpc_id = "${aws_vpc.TF_Vpc.id}"
  tags = {
    Name = "PublicRouteTable"
  }
}

#PrivateRouteTable Creation
resource "aws_route_table" "PrivateRouteTable" {
  vpc_id = "${aws_vpc.TF_Vpc.id}"
  tags = {
    Name = "PrivateRouteTable"
  }
}

#Attach IGW to PublicRT
resource "aws_route" "route1" {
  route_table_id            = "${aws_route_table.PublicRouteTable.id}"
  destination_cidr_block    = "0.0.0.0/0"
  gateway_id = "${aws_internet_gateway.igw.id}"
  depends_on                = [aws_route_table.PublicRouteTable]
}

#Attach NAT to PrivateRT
resource "aws_route" "route2" {
  route_table_id            = "${aws_route_table.PrivateRouteTable.id}"
  destination_cidr_block    = "0.0.0.0/0"
  nat_gateway_id = "${aws_nat_gateway.nat.id}"
  depends_on                = [aws_route_table.PrivateRouteTable]
}

#Associate PublicSubnet1 with PublicRT
resource "aws_route_table_association" "PublicSubnet1RTAssociation" {
  subnet_id      = "${aws_subnet.PublicSubnet1.id}"
  route_table_id = "${aws_route_table.PublicRouteTable.id}"
}

#Associate PublicSubnet2 with PublicRT
resource "aws_route_table_association" "PublicSubnet2RTAssociation" {
  subnet_id      = "${aws_subnet.PublicSubnet2.id}"
  route_table_id = "${aws_route_table.PublicRouteTable.id}"
}

#Associate PricvateSubnet with PrivateRT
resource "aws_route_table_association" "PrivateRTAssociation" {
  subnet_id      = "${aws_subnet.PrivateSubnet.id}"
  route_table_id = "${aws_route_table.PrivateRouteTable.id}"
}

#-------------------------------------------Web Server--------------------------------------------
#WebServer SecuityGroup
resource "aws_security_group" "ec2_sg" {
  depends_on = [aws_security_group.lb_SG]
  name        = "Web_Server_SG"
  description = "Connect EC2 "
  vpc_id      = "${aws_vpc.TF_Vpc.id}"
  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    security_groups  = ["${aws_security_group.lb_SG.id}"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "Web_App_SG"
  }
}

#WebServer Creation
resource "aws_instance" "instance" {
  depends_on = [aws_route.route2]
  ami           = var.ami_id
  instance_type = "t2.micro"
  availability_zone = var.AZ1
  subnet_id     = "${aws_subnet.PrivateSubnet.id}"
  security_groups = ["${aws_security_group.ec2_sg.id}"]
  key_name      = var.ec2_key
  tags = {
    Name = "WebApp_Server"
  }
  user_data = <<-EOF
              #! /bin/bash
              sudo yum update -y
              sudo yum install -y httpd
              sudo yum install unzip -y
              sudo chmod 777 /var/www/
              sudo curl "${var.url}"/dist.zip --output dist.zip
              sudo unzip dist.zip 
              sudo cp -rf dist/cisco/* /var/www/html/
              sudo service httpd start
              sudo chkconfig httpd on
              EOF

}

#-------------------------------------------Load Balancer--------------------------------------------
#LoadBalancer SecuityGroup
resource "aws_security_group" "lb_SG" {
  name        = "ALB_Sg"
  description = "Allow all inbound traffic"
  vpc_id      = "${aws_vpc.TF_Vpc.id}"

  ingress {
    from_port   = 80
    to_port     = 80
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
    Name = "ALB_Sg"
  }
}

#LoadBalancer Creation
resource "aws_lb" "lb" {
  name               = "lb"
  internal           = false
  load_balancer_type = "application"
  enable_deletion_protection = false
  subnets = ["${aws_subnet.PublicSubnet1.id}", "${aws_subnet.PublicSubnet2.id}"]
  security_groups = ["${aws_security_group.lb_SG.id}"]

}

#LoadBalancer TargetGroup
resource "aws_lb_target_group" "lbtargetgrp" {
  name     = "lbtargetgrp"
  port     = 80
  protocol = "HTTP"
  vpc_id      = "${aws_vpc.TF_Vpc.id}"
  depends_on = [aws_vpc.TF_Vpc]

}

#LoadBalancer Listener
resource "aws_alb_listener" "lb_listener" {
  load_balancer_arn = "${aws_lb.lb.id}"
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = "${aws_lb_target_group.lbtargetgrp.id}"
    type             = "forward"
  }
}

#LoadBalancer Target Group Attachment
resource "aws_lb_target_group_attachment" "lb_target_group_attachment" {
  target_group_arn = "${aws_lb_target_group.lbtargetgrp.arn}"
  target_id        = "${aws_instance.instance.id}"
  port             = 80
}


#-----------------------------------------------Lambda--------------------------------------------------
#Lambda Role Creation
resource "aws_iam_role" "lambda_role" {
  name = "lambda-role"
  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
        "Action": "sts:AssumeRole",
        "Principal": {
            "Service": "lambda.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
        }
    ]
   }
EOF
}

#Lambda Policy Creation
resource "aws_iam_policy" "lambda_policy" {
  name        = "lambda_policy"
  description = "IAM Policy for the lambda"
  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:*"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "logs:CreateLogGroup",
            "Resource": "arn:aws:logs:${var.aws_region}:${var.account_id}:*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": [
                "arn:aws:logs:${var.aws_region}:${var.account_id}:log-group:/aws/lambda/*"
            ]
        }
    ]
  }
EOF
}

#Attach Policy to Lambda Role
resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

#Lambda Function creation
resource "aws_lambda_function" "lambda" {
  filename                       = "WebAppLambda.zip"
  function_name                  = "ImageStorageLambda"
  role                           = aws_iam_role.lambda_role.arn
  handler                        = "AWSLambda1::AWSLambda1.Function::FunctionHandler"
  memory_size                    = "528"
  runtime                        = "dotnetcore3.1"
  timeout                        = 300

}

#---------------------------------------------API Gateway--------------------------------------------------
#CloudWatch Log Group for API Gateway
resource "aws_cloudwatch_log_group" "LogGroup" {
  name              = "API-Gateway-Execution-Logs_${aws_api_gateway_rest_api.api.id}/web"
  retention_in_days = 14
}

#Role for Cloudwatch Logs
resource "aws_iam_role" "cloudwatch" {
  name = "api_gateway_cloudwatch_global"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "apigateway.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

#Policy for Cloudwatch Logs
resource "aws_iam_role_policy" "cloudwatch" {
  name = "default"
  role = "${aws_iam_role.cloudwatch.id}"

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:DescribeLogGroups",
                "logs:DescribeLogStreams",
                "logs:PutLogEvents",
                "logs:GetLogEvents",
                "logs:FilterLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
EOF
}

resource "aws_api_gateway_account" "api_gateway_account" {
  cloudwatch_role_arn = "${aws_iam_role.cloudwatch.arn}"
}

#Enable CloudWatch Logs
resource "aws_api_gateway_method_settings" "s" {
  stage_name  = "${aws_api_gateway_deployment.deployment.stage_name}"
  method_path = "*/*"
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  settings {
    logging_level      = "ERROR"
    data_trace_enabled = true
    metrics_enabled = true
  }
}

#Lambda permission for API Gateway 
resource "aws_lambda_permission" "apigw" {
  statement_id = "AllowAPIGatewayInvoke"
  action = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.lambda.function_name}"
  principal = "apigateway.amazonaws.com"
  source_arn = "arn:aws:execute-api:${var.aws_region}:${var.account_id}:${aws_api_gateway_rest_api.api.id}/*/POST/"
  depends_on    = [aws_api_gateway_rest_api.api]
}

#API Gateway Creation
resource "aws_api_gateway_rest_api" "api" {
  name        = "api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

#To Enable CORS
#API Gateway "OPTIONS" Method Creation
resource "aws_api_gateway_method" "options_method" {
  rest_api_id   = "${aws_api_gateway_rest_api.api.id}"
  resource_id   = "${aws_api_gateway_rest_api.api.root_resource_id}"
  http_method   = "OPTIONS"
  authorization = "NONE"
}

#API Gateway Method Response
resource "aws_api_gateway_method_response" "options_200" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id = "${aws_api_gateway_rest_api.api.root_resource_id }"
  http_method = "${aws_api_gateway_method.options_method.http_method}"
  status_code = 200
  response_models = {
    "application/json" = "Empty"
  }
  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = true,
    "method.response.header.Access-Control-Allow-Methods" = true,
    "method.response.header.Access-Control-Allow-Origin" = true
  }
  depends_on = [
    aws_api_gateway_method.options_method
  ]
}

#API Gateway Integration
resource "aws_api_gateway_integration" "options_integration" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id = "${aws_api_gateway_rest_api.api.root_resource_id }"
  http_method = "${aws_api_gateway_method.options_method.http_method}"
  type = "MOCK"
  request_templates = {
    "application/json" = <<EOF
    { "statusCode": 200 }
  EOF
  }
  depends_on = [aws_api_gateway_method.options_method]
}

#API Gateway Integration response
resource "aws_api_gateway_integration_response" "options_integration_response" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id = "${aws_api_gateway_rest_api.api.root_resource_id }"
  http_method = "${aws_api_gateway_method.options_method.http_method}"
  status_code = "${aws_api_gateway_method_response.options_200.status_code}"

  response_parameters = {
    "method.response.header.Access-Control-Allow-Headers" = "'Content-Type,X-Amz-Date,Authorization,X-Api-Key,X-Amz-Security-Token'",
    "method.response.header.Access-Control-Allow-Methods" = "'OPTIONS,POST'",
    "method.response.header.Access-Control-Allow-Origin" = "'*'"
  }

  response_templates = {
    "application/json" = ""
  }

  depends_on = [
    aws_api_gateway_method_response.options_200
  ]
}

#POST Method 
#API Gateway "POST" Method Creation
resource "aws_api_gateway_method" "request_method" {
  rest_api_id   = "${aws_api_gateway_rest_api.api.id}"
  resource_id   = "${aws_api_gateway_rest_api.api.root_resource_id}"
  http_method   = "POST"
  authorization = "NONE"
}

#API Gateway Response
resource "aws_api_gateway_method_response" "response_method" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id = "${aws_api_gateway_rest_api.api.root_resource_id}"
  http_method = "${aws_api_gateway_integration.request_method_integration.http_method}"
  status_code = "200"
  response_parameters = {
    "method.response.header.Access-Control-Allow-Origin" = true
  }
  response_models = {
    "application/json" = "Empty"
  }
}

#API Gateway Method Integration
resource "aws_api_gateway_integration" "request_method_integration" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id   = "${aws_api_gateway_rest_api.api.root_resource_id }"
  http_method = "${aws_api_gateway_method.request_method.http_method}"
  type        = "AWS"
  uri         = "${aws_lambda_function.lambda.invoke_arn}"
  # AWS lambda can only be invoked with the POST method
  integration_http_method = "POST"
}

#API Gateway Integration Response
resource "aws_api_gateway_integration_response" "response_method_integration" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id   = "${aws_api_gateway_rest_api.api.root_resource_id }"
  http_method = "${aws_api_gateway_method_response.response_method.http_method}"
  status_code = "${aws_api_gateway_method_response.response_method.status_code}"
  response_templates = {
    "application/json" = ""
  }
}

#API Gateway Deployment
resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  stage_name = "web"
  depends_on  = [
    aws_api_gateway_integration.request_method_integration,
    aws_api_gateway_integration.options_integration,
    aws_api_gateway_integration_response.options_integration_response,
    aws_api_gateway_integration_response.response_method_integration
  ]
}

#Custom domain mapping
resource "aws_api_gateway_base_path_mapping" "test" {
  api_id      = "${aws_api_gateway_rest_api.api.id}"
  stage_name  = "${aws_api_gateway_deployment.deployment.stage_name}"
  domain_name = var.domain_name
}