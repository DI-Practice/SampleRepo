resource "aws_iam_role" "iam_test" {
  name = "${var.name_prefix}_iam_test"

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

resource "aws_lambda_function" "test_lambda" {
  filename         = "${path.module}/testing.py.zip"
  function_name    = "${var.name_prefix}_${var.name_suffix}_${var.environment}_test"
  role             = "${aws_iam_role.iam_test.arn}"
  handler          = "testing.handler"
  source_code_hash = "${filebase64sha256("${path.module}/testing.py.zip")}"
  runtime          = "python3.7"

}