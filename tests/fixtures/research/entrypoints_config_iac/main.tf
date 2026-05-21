resource "aws_security_group" "public_web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_iam_policy" "wildcard" {
  policy = "{\"Statement\":[{\"Principal\":\"*\",\"Action\":\"*\"}]}"
}
