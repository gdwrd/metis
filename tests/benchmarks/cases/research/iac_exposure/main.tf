resource "aws_security_group" "public_web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}

