resource "aws_iam_role" "iam_hello" {
  name = "${var.name_prefix}_iam_hello"

  assume_role_policy = <<EOF
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

resource "aws_lambda_function" "hello_lambda" {
  filename         = "${path.module}/helloworld.py.zip"
  function_name    = "${var.name_prefix}_${var.name_suffix}_${var.environment}_hello"
  role             = "${aws_iam_role.iam_hello.arn}"
  handler          = "helloworld.handler"
  source_code_hash = "${filebase64sha256("${path.module}/helloworld.py.zip")}"
  runtime          = "python3.7"

}