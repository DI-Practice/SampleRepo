resource "aws_iam_role" "iam_message" {
  name = "${var.name_prefix}_iam_message"

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

resource "aws_lambda_function" "message_lambda" {
  filename         = "${path.module}/message.py.zip"
  function_name    = "${var.name_prefix}_${var.name_suffix}_${var.environment}_message"
  role             = "${aws_iam_role.iam_message.arn}"
  handler          = "message.handler"
  source_code_hash = "${filebase64sha256("${path.module}/message.py.zip")}"
  runtime          = "python3.7"

}