// This is used to set the version reported by the binary through an environment
// variable. This is mainly useful when building out of a git context, like in
// CI, where we don't have the full commit history available
variable "VERGEN_GIT_DESCRIBE" {}

target "docker-metadata-action" {}

// This sets the platforms and is further extended by GitHub Actions to set the
// output and the cache locations
target "base" {
  args = {
    // This is set so that when we use a git context, the .git directory is
    // present, as we may be infering the version at build time out of it
    BUILDKIT_CONTEXT_KEEP_GIT_DIR = 1

    // Pass down the version from an external git describe source
    VERGEN_GIT_DESCRIBE = "${VERGEN_GIT_DESCRIBE}"
  }

  platforms = [
    "linux/amd64",
    "linux/arm64",
  ]
}

target "release" {
  inherits = ["base", "docker-metadata-action"]
}
