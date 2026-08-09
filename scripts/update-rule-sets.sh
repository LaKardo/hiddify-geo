#!/usr/bin/env bash
set -euo pipefail

readonly SING_BOX_VERSION="1.13.18"
readonly MIHOMO_VERSION="1.19.29"
readonly SOURCE_BASE="https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set"

output_dir="${1:-output}"
mkdir -p "$output_dir/block" "$output_dir/country"

# Keep the original hiddify-geo source-to-destination mapping, including aliases.
readonly rule_sets=(
  "geoip-phishing|block/geoip-phishing"
  "geoip-malware|block/geoip-malware"
  "geosite-phishing|block/geosite-phishing"
  "geosite-malware|block/geosite-malware"
  "geosite-cryptominers|block/geosite-cryptominers"
  "geosite-category-ads-all|block/geosite-category-ads-all"
  "geoip-ir|country/geoip-ir"
  "geoip-cn|country/geoip-cn"
  "geoip-af|country/geoip-af"
  "geoip-ru|country/geoip-ru"
  "geoip-id|country/geoip-id"
  "geoip-tr|country/geoip-tr"
  "geosite-ir|country/geosite-ir"
  "geosite-cn|country/geosite-cn"
  "geosite-category-ru|country/geosite-ru"
  "geosite-category-gov-ru|country/geosite-id"
  "geosite-category-gov-ru|country/geosite-tr"
  "geoip-br|country/geoip-br"
  "geosite-ir|country/geosite-br"
  "geosite-ir|country/geosite-af"
)

for mapping in "${rule_sets[@]}"; do
  source_name="${mapping%%|*}"
  destination="${mapping#*|}"
  temporary_file="$(mktemp)"
  curl --fail --location --retry 3 --silent --show-error \
    "$SOURCE_BASE/$source_name.srs" --output "$temporary_file"
  mv "$temporary_file" "$output_dir/$destination.srs"
done

tool_dir="$(mktemp -d)"
trap 'rm -rf "$tool_dir"' EXIT

curl --fail --location --retry 3 --silent --show-error \
  "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/sing-box-$SING_BOX_VERSION-linux-amd64.tar.gz" \
  --output "$tool_dir/sing-box.tar.gz"
tar -xzf "$tool_dir/sing-box.tar.gz" -C "$tool_dir"
sing_box="$tool_dir/sing-box-$SING_BOX_VERSION-linux-amd64/sing-box"

curl --fail --location --retry 3 --silent --show-error \
  "https://github.com/MetaCubeX/mihomo/releases/download/v$MIHOMO_VERSION/mihomo-linux-amd64-compatible-v$MIHOMO_VERSION.gz" \
  --output "$tool_dir/mihomo.gz"
gzip -dc "$tool_dir/mihomo.gz" > "$tool_dir/mihomo"
chmod +x "$tool_dir/mihomo"
mihomo="$tool_dir/mihomo"

unsupported_rules=0
while IFS= read -r -d '' srs_file; do
  json_file="$tool_dir/rule-set.json"
  text_file="$tool_dir/rule-set.txt"
  mrs_file="${srs_file%.srs}.mrs"

  "$sing_box" rule-set decompile "$srs_file" --output "$json_file"

  if [[ "$(basename "$srs_file")" == geoip-* ]]; then
    behavior="ipcidr"
    jq -r '.rules[].ip_cidr[]?' "$json_file" | sort -u > "$text_file"
  else
    behavior="domain"
    jq -r '
      .rules[] |
      (.domain[]?),
      (.domain_suffix[]? | if startswith(".") then "+" + . else "+." + . end)
    ' "$json_file" | sort -u > "$text_file"
    skipped="$(jq '[.rules[] | (.domain_keyword[]?, .domain_regex[]?)] | length' "$json_file")"
    unsupported_rules=$((unsupported_rules + skipped))
  fi

  test -s "$text_file"
  "$mihomo" convert-ruleset "$behavior" text "$text_file" "$mrs_file"
  test -s "$mrs_file"
done < <(find "$output_dir" -type f -name '*.srs' -print0)

validation_config="$tool_dir/validate.yaml"
{
  echo "mixed-port: 7890"
  echo "mode: rule"
  echo "log-level: silent"
  echo "rule-providers:"
  provider_index=0
  while IFS= read -r mrs_file; do
    behavior="domain"
    [[ "$(basename "$mrs_file")" == geoip-* ]] && behavior="ipcidr"
    relative_path="${mrs_file#"$output_dir"/}"
    echo "  provider_$provider_index:"
    echo "    type: file"
    echo "    behavior: $behavior"
    echo "    format: mrs"
    echo "    path: ./$relative_path"
    provider_index=$((provider_index + 1))
  done < <(find "$output_dir" -type f -name '*.mrs' | sort)
  echo "rules:"
  for ((index = 0; index < provider_index; index++)); do
    echo "  - RULE-SET,provider_$index,DIRECT"
  done
  echo "  - MATCH,DIRECT"
} > "$validation_config"

srs_count="$(find "$output_dir" -type f -name '*.srs' | wc -l)"
mrs_count="$(find "$output_dir" -type f -name '*.mrs' | wc -l)"
[[ "$srs_count" -eq "${#rule_sets[@]}" ]]
[[ "$mrs_count" -eq "$srs_count" ]]

"$mihomo" -t -d "$output_dir" -f "$validation_config"
echo "Validated $mrs_count MRS files with Mihomo $MIHOMO_VERSION."
if ((unsupported_rules > 0)); then
  echo "Warning: omitted $unsupported_rules regex/keyword rules unsupported by MRS domain behavior." >&2
fi
