# hiddify-geo

Hourly GeoIP and Geosite rule sets for both sing-box (`.srs`) and Mihomo (`.mrs`). Generated files are published to the [`rule-set`](../../tree/rule-set) branch while the generation pipeline stays on `main`.

## Mihomo usage

Use `behavior: domain` for `geosite-*` files and `behavior: ipcidr` for `geoip-*` files:

```yaml
rule-providers:
  iran-domains:
    type: http
    behavior: domain
    format: mrs
    url: https://raw.githubusercontent.com/LaKardo/hiddify-geo/rule-set/country/geosite-ir.mrs
    path: ./rules/geosite-ir.mrs
    interval: 3600

  iran-ips:
    type: http
    behavior: ipcidr
    format: mrs
    url: https://raw.githubusercontent.com/LaKardo/hiddify-geo/rule-set/country/geoip-ir.mrs
    path: ./rules/geoip-ir.mrs
    interval: 3600
```

## Generation and validation

The pipeline preserves the original source mapping from [Chocolate4U/Iran-sing-box-rules](https://github.com/Chocolate4U/Iran-sing-box-rules). It keeps each `.srs`, decompiles it with sing-box, converts its domain or CIDR payload with Mihomo's supported `convert-ruleset` command, and writes the sibling `.mrs` file.

Every run checks that all 20 SRS files have matching MRS files, then loads every MRS provider with `mihomo -t`. Pull requests run the same validation and upload the generated MRS files as a workflow artifact.

MRS supports only `domain` and `ipcidr` behavior. Regex and keyword rules that cannot be represented by MRS are reported by the build and remain available in the corresponding SRS file.
