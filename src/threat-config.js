// Public verification key; private key is never bundled.
export const THREAT_CONFIG = {
  "manifestURL": "https://github.com/poohpak/munimen-threat-data/releases/download/threat-feed/manifest.json",
  "artifactBase": "https://github.com/poohpak/munimen-threat-data/releases/download/threat-feed/",
  "keys": {
    "munimen-2026-11-14": {
      "key_ops": [
        "verify"
      ],
      "ext": true,
      "kty": "EC",
      "x": "Gyx0zD3NZ3qsf4-K1CDielkjC69qOkdNWvf-xhqFHuI",
      "y": "azdfyzdnBsSheJhTWoSFxr45wuj8yGAJUC3odENy7fo",
      "crv": "P-256"
    }
  }
};
