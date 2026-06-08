terraform {
  required_providers {
    docker = { source = "kreuzwerker/docker", version = "~> 3.0" }
  }
}
# Minimal container deploy. Swap the provider block for aws_ecs_service,
# azurerm_container_app, or google_cloud_run_v2_service as needed.
provider "docker" {}
resource "docker_image" "certsearch" { name = "ghcr.io/cognis-digital/certsearch:latest" }
resource "docker_container" "certsearch" {
  name  = "certsearch"
  image = docker_image.certsearch.image_id
  ports { internal = 8000 external = 8000 }
}
