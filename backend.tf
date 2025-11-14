terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# For production, use S3 backend:
# terraform {
#   backend "s3" {
#     bucket         = "your-terraform-state-bucket"
#     key            = "security-groups/vpc-${var.vpc_id}/terraform.tfstate"
#     region         = "us-east-1"
#     encrypt        = true
#     dynamodb_table = "terraform-state-locks"
#   }
# }
