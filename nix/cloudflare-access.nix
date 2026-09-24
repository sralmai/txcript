# Cloudflare Access in front of the service, as a separate import.
#
# This is the whole point of the split: the service package knows nothing
# about Cloudflare, and changing the authentication story means importing a
# different module rather than rebuilding or reconfiguring the service. An
# OIDC or mTLS module would sit here as a peer.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.txcript-share.cloudflareAccess;
in
{
  options.services.txcript-share.cloudflareAccess = {
    enable = lib.mkEnableOption "Cloudflare Access in front of txcript-share";

    tunnelCredentialsFile = lib.mkOption {
      type = lib.types.path;
      description = "cloudflared tunnel credentials, from sops/agenix.";
    };

    identityHeader = lib.mkOption {
      type = lib.types.str;
      default = "cf-access-authenticated-user-email";
      description = ''
        The header cloudflared presents to the origin. It is hashed into a
        principal id, so any length of address works.

        The service trusts it, so **the tunnel must be the only route in**.
        With the service on loopback that holds by construction; expose it on
        another interface and anyone who can reach it can set this header and
        become anyone.
      '';
    };
  };

  config = lib.mkIf (cfg.enable && config.services.txcript-share.enable) {
    # Selecting the identity source is all this module does to the service.
    services.txcript-share.identity = {
      kind = "forwarded_header";
      header = cfg.identityHeader;
    };

    # Loopback only. The tunnel is the ingress; nothing else should be.
    services.txcript-share.listenAddress = lib.mkDefault "127.0.0.1";

    systemd.services.cloudflared-txcript-share = {
      description = "cloudflared tunnel for txcript-share";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.cloudflared}/bin/cloudflared tunnel --no-autoupdate run --credentials-file \${CREDENTIALS_DIRECTORY}/tunnel";
        LoadCredential = [ "tunnel:${cfg.tunnelCredentialsFile}" ];
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = "5s";
      };
    };
  };
}
