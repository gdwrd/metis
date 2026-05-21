resource "aws_ssm_parameter" "secret_token" {
  name  = "/service/token"
  type  = "String"
  env   = "prod"
  value = "hardcoded-token"
}

resource "aws_ssm_parameter" "vaulted_token" {
  name  = "/service/vaulted"
  type  = "SecureString"
  env   = "prod"
  value = vault("service/token")
}
