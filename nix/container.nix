# An OCI image containing exactly the binary's closure.
#
# `buildLayeredImage` needs no Dockerfile and no upstream base image, so
# there is no distro to track CVEs for — the image holds the binary, its
# libraries, and CA certificates, and nothing else. That is a materially
# smaller surface than `FROM debian`.
{
  dockerTools,
  cacert,
  lib,
  share-server,
}:

dockerTools.buildLayeredImage {
  name = "txcript-share-server";
  tag = "latest";

  contents = [
    share-server
    # Needed to verify TLS when the store is S3 or R2.
    cacert
  ];

  config = {
    # Unprivileged. The process binds 8787 and reads one configuration file,
    # so it never needs root — while the NixOS path for the same binary is
    # careful to use `DynamicUser`. `nobody`, because the image has no
    # /etc/passwd to name anyone else.
    User = "65534:65534";
    Entrypoint = [ (lib.getExe share-server) ];
    # Overridable: `docker run … image /path/to/other.toml`.
    Cmd = [ "/etc/txcript-share/config.toml" ];
    ExposedPorts."8787/tcp" = { };
    Env = [ "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt" ];
  };
}
