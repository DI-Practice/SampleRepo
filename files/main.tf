provider "aws" {
  region     = var.aws_region
}

#Network Creation
#Vpc
resource "aws_vpc" "TF_Vpc" {
  cidr_block       = "172.16.0.0/16"
  enable_dns_hostnames  = true
  instance_tenancy = "default"
  tags = {
    Name = "Vpc"
  }
}

#PublicSubnet1
resource "aws_subnet" "PublicSubnet1" {
  vpc_id     = "${aws_vpc.TF_Vpc.id}"
  cidr_block = "172.16.1.0/24"
  availability_zone = "us-east-1a"
  map_public_ip_on_launch = true

   tags = {
       Name = "PublicSubnet1"
   }
}

#PublicSubnet2
resource "aws_subnet" "PublicSubnet2" {
  vpc_id     = "${aws_vpc.TF_Vpc.id}"
  cidr_block = "172.16.2.0/24"
  availability_zone = "us-east-1b"
  map_public_ip_on_launch = true
  tags = {
       Name = "PublicSubnet2"
   }
}

#PrivateSubnet
resource "aws_subnet" "PrivateSubnet" {
  vpc_id     = "${aws_vpc.TF_Vpc.id}"
  cidr_block = "172.16.3.0/24"
  availability_zone = "us-east-1a"
  tags = {
       Name = "PrivateSubnet"
   }
}

#EIP
resource "aws_eip" "eip" {
  #depends_on                = ["aws_internet_gateway.igw"]
  vpc = true
}

#NAT gateway
resource "aws_nat_gateway" "nat" {
  allocation_id = "${aws_eip.eip.id}"
  subnet_id     = "${aws_subnet.PublicSubnet1.id}"
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "NAT"
  }
}

#IGW
resource "aws_internet_gateway" "igw" {
  vpc_id = "${aws_vpc.TF_Vpc.id}"

  tags = {
    Name = "IGW"
  }
}

#PublicRouteTable
resource "aws_route_table" "PublicRouteTable" {
  vpc_id = "${aws_vpc.TF_Vpc.id}"
  tags = {
    Name = "PublicRouteTable"
  }
}

#PrivateRouteTable
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

#SG
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

#Instance
resource "aws_instance" "instance" {
  depends_on = [aws_route.route2]
  ami           = "ami-0e9089763828757e1"
  instance_type = "t2.micro"
  availability_zone = "us-east-1a"
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
              curl https://testrgupload.s3.ap-south-1.amazonaws.com/dist.zip --output dist.zip
              unzip dist.zip 
              sudo cp -rf dist/cisco/* /var/www/html/
              sudo service httpd start
              sudo chkconfig httpd on
              EOF

}

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

#LoadBalancer
resource "aws_lb" "lb" {
  name               = "lb"
  internal           = false
  load_balancer_type = "application"
  enable_deletion_protection = false
  subnets = ["${aws_subnet.PublicSubnet1.id}", "${aws_subnet.PublicSubnet2.id}"]
  security_groups = ["${aws_security_group.lb_SG.id}"]

}

resource "aws_lb_target_group" "lbtargetgrp" {
  name     = "lbtargetgrp"
  port     = 80
  protocol = "HTTP"
  vpc_id      = "${aws_vpc.TF_Vpc.id}"
  depends_on = [aws_vpc.TF_Vpc]

}


resource "aws_alb_listener" "lb_listener" {
  load_balancer_arn = "${aws_lb.lb.id}"
  port              = "80"
  protocol          = "HTTP"

  default_action {
    target_group_arn = "${aws_lb_target_group.lbtargetgrp.id}"
    type             = "forward"
  }
}
resource "aws_lb_target_group_attachment" "lb_target_group_attachment" {
  target_group_arn = "${aws_lb_target_group.lbtargetgrp.arn}"
  target_id        = "${aws_instance.instance.id}"
  port             = 80
}


#Lambda and API Gateway
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

resource "aws_iam_role_policy_attachment" "lambda_policy_attachment" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

#S3 Bucket creation
resource "aws_s3_bucket" "s3_bucket" {
  bucket = var.bucket_name
  acl    = "private"
}

# Lambda Function creation
resource "aws_lambda_function" "lambda" {
  filename                       = "WebAppLambda.zip"
  function_name                  = "ImageStorageLambda"
  role                           = aws_iam_role.lambda_role.arn
  handler                        = "AWSLambda1::AWSLambda1.Function::FunctionHandler"
  memory_size                    = "528"
  runtime                        = "dotnetcore3.1"
  timeout                        = 300

}

#API Gateway
#Rest API Gateway creation
resource "aws_api_gateway_rest_api" "api" {
  name        = "api"
  endpoint_configuration {
    types = ["REGIONAL"]
  }
}

#API Gateway Deployment
resource "aws_api_gateway_deployment" "deployment" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  stage_name = "web"
  depends_on  = ["aws_api_gateway_integration.request_method_integration", "aws_api_gateway_integration_response.response_method_integration"]
}

#API Gateway Method Creation
resource "aws_api_gateway_method" "request_method" {
  rest_api_id   = "${aws_api_gateway_rest_api.api.id}"
  resource_id   = "${aws_api_gateway_rest_api.api.root_resource_id }"
  http_method   = "POST"
  authorization = "NONE"
}

#API Gateway Method Integration
resource "aws_api_gateway_integration" "request_method_integration" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id   = "${aws_api_gateway_rest_api.api.root_resource_id }"
  http_method = "${aws_api_gateway_method.request_method.http_method}"
  type        = "AWS"
  uri         = "${aws_lambda_function.lambda.invoke_arn}"

  # AWS lambdas can only be invoked with the POST method
  integration_http_method = "POST"
}

#API Gateway Response
resource "aws_api_gateway_method_response" "response_method" {
  rest_api_id = "${aws_api_gateway_rest_api.api.id}"
  resource_id   = "${aws_api_gateway_rest_api.api.root_resource_id }"
  http_method = "${aws_api_gateway_integration.request_method_integration.http_method}"
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }
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

resource "aws_lambda_permission" "apigw" {
  statement_id = "AllowAPIGatewayInvoke"
  action = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.lambda.function_name}"
  principal = "apigateway.amazonaws.com"
  source_arn = "arn:aws:execute-api:${var.aws_region}:${var.account_id}:${aws_api_gateway_rest_api.api.id}/*/POST/"
  depends_on    = ["aws_api_gateway_rest_api.api"]
}

#Custom domain mapping
resource "aws_api_gateway_base_path_mapping" "test" {
  api_id      = "${aws_api_gateway_rest_api.api.id}"
  stage_name  = "${aws_api_gateway_deployment.deployment.stage_name}"
  domain_name = var.domain_name
}




