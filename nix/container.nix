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
    Entrypoint = [ (lib.getExe share-server) ];
    # Overridable: `docker run … image /path/to/other.toml`.
    Cmd = [ "/etc/txcript-share/config.toml" ];
    ExposedPorts."8787/tcp" = { };
    Env = [ "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt" ];
  };
}
