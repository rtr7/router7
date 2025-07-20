{
  pkgs ? import <nixpkgs> { },
}:
pkgs.mkShell {
  packages = with pkgs; [
    dnsmasq
    dig
    ndisc6
    nftables
  ];
}
