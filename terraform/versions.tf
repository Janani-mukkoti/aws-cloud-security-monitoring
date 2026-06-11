# versions.tf
# Pins the Terraform CLI and provider versions so that the configuration is
# reproducible across machines and CI. Always pin providers in real projects to
# avoid surprise breaking changes when a new major version is released.

terraform {
  # Terraform 1.5 introduced `check` blocks and import blocks; we require it as
  # a sensible modern baseline.
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    # Used to build the Lambda deployment package (zip) from source at plan time
    # so no manual packaging step is required.
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }
}
