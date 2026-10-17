{
  description = "Logos module for EIP-191 eth-allowlist signing (client-side auth vector producer)";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder/6ef42ea8661121831ece79e6b702e27ac1cf46e7";
  };

  outputs = inputs@{ logos-module-builder, ... }:
    logos-module-builder.lib.mkLogosModule {
      src = ./.;
      configFile = ./metadata.json;
      flakeInputs = inputs;
    };
}
