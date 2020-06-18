provider "aws" {
  region  = var.aws_region
}

locals {
  name_prefix = "${var.name_prefix}"
  name_suffix = "${var.name_suffix}"
  environment = "${var.environment}"
}

module "hello" {
    source          = "./modules/HELLO"
    name_prefix     = local.name_prefix
    name_suffix     = local.name_suffix
    environment     = local.environment
}

module "test" {
    source          = "./modules/TESTING"
    name_prefix     = local.name_prefix
    name_suffix     = local.name_suffix
    environment     = local.environment
}

module "message" {
    source          = "./modules/MESSAGE"
    name_prefix     = local.name_prefix
    name_suffix     = local.name_suffix
    environment     = local.environment
}