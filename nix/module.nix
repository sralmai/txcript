# The NixOS service module.
#
# It knows nothing about Cloudflare, OIDC, or any other identity provider —
# that is `cloudflare-access.nix`'s job, imported separately. Swapping the
# authentication story must not rebuild or reconfigure the service itself.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.txcript-share;

  # The service reads exactly one file and nothing else. Generating it here
  # means a NixOS deployment never hand-writes TOML.
  configFile = (pkgs.formats.toml { }).generate "txcript-share.toml" (
    {
      listen = "${cfg.listenAddress}:${toString cfg.port}";
      identity = cfg.identity;
      store = cfg.store;
      policy = cfg.policy;
    }
    // lib.optionalAttrs (cfg.limits != { }) { limits = cfg.limits; }
  );
in
{
  options.services.txcript-share = {
    enable = lib.mkEnableOption "the txcript shared transcript service";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.share-server;
      description = "The server package to run.";
    };

    listenAddress = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
      description = ''
        Loopback by default. This service expects an authenticating proxy in
        front of it; binding a public interface without one publishes every
        transcript.
      '';
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8787;
    };

    identity = lib.mkOption {
      type = lib.types.attrs;
      example = {
        kind = "forwarded_header";
        header = "x-forwarded-user";
      };
      description = ''
        The identity block, written verbatim into the configuration file.
        Normally set by an authentication module rather than by hand.
      '';
    };

    store = lib.mkOption {
      type = lib.types.attrs;
      default = {
        kind = "filesystem";
        root = "/var/lib/txcript-share";
      };
    };

    policy = lib.mkOption {
      type = lib.types.attrs;
      default = {
        kind = "owner_prefix";
      };
    };

    limits = lib.mkOption {
      type = lib.types.attrs;
      default = { };
    };

    credentialFiles = lib.mkOption {
      type = lib.types.attrsOf lib.types.path;
      default = { };
      example = lib.literalExpression ''{ tokens = config.age.secrets.tokens.path; }'';
      description = ''
        Files loaded through systemd credentials and exposed to the service
        at `''${CREDENTIALS_DIRECTORY}/<name>`. Secrets reach the service as
        paths rather than environment values, which is what lets sops,
        agenix, and plain files all work without the binary knowing the
        difference.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.txcript-share = {
      description = "txcript shared transcript service";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} ${configFile}";
        DynamicUser = true;
        StateDirectory = "txcript-share";
        LoadCredential = lib.mapAttrsToList (name: path: "${name}:${path}") cfg.credentialFiles;

        # The service reads one config file, writes one state directory, and
        # talks to the network. Everything else is denied.
        NoNewPrivileges = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        RestrictNamespaces = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];

        Restart = "on-failure";
        RestartSec = "5s";
      };
    };
  };
}
