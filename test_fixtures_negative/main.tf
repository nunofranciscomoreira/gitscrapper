resource "aws_db_instance" "app" {
  identifier = "app-db"
  username   = var.db_username
  password   = var.db_password
}

resource "aws_secretsmanager_secret_version" "api" {
  secret_id     = aws_secretsmanager_secret.api.id
  secret_string = "${var.api_secret}"
}

locals {
  api_token = "${data.vault_generic_secret.app.data["token"]}"
}
