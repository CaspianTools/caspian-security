# Synthetic Terraform fixture. Every misconfiguration is deliberate.

# TF001 — wide-open ingress
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# TF002 — public S3 bucket
resource "aws_s3_bucket" "public" {
  bucket = "my-bucket"
  acl    = "public-read"
}

# TF003 — wildcard IAM action
data "aws_iam_policy_document" "bad" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

# TF004 — publicly accessible RDS
resource "aws_db_instance" "db" {
  publicly_accessible = true
  master_username     = "admin"
  # TF006 — hardcoded master password
  master_password     = "hunter2-database"
}

# TF008 — admin-access managed policy
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
