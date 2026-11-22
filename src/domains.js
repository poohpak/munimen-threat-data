import { parse } from "tldts";

function canonicalDnsName(value, compatibilityLabels) {
  if (typeof value !== "string" || !value || /[\s/@:#?\\\[\]]/.test(value))
    return null;
  try {
    const hostname = new URL(`https://${value}`).hostname.replace(/\.$/, "");
    if (
      !(compatibilityLabels ? /^[\x21-\x7e]+$/ : /^[a-z0-9.-]+$/).test(hostname) ||
      hostname
        .split(".")
        .some(
          (label) =>
            !label ||
            !compatibilityLabels && (label.startsWith("-") || label.endsWith("-")) ||
            label.length > 63,
        ) ||
      hostname.length > 253
    )
      return null;
    return hostname;
  } catch {
    return null;
  }
}

// Reference imports and sender alignment keep strict DNS hostname syntax.
export const canonicalDomain = value => canonicalDnsName(value, false);
// Browsers can navigate to compatibility labels such as _service or z!service.
// Preserve those labels while inspecting the rest of the hostname; rejecting
// the entire name here would erase a copied official domain before comparison.
export const canonicalHostname = value => canonicalDnsName(value, true);

export function registeredDomain(hostname) {
  return parse(hostname, { allowPrivateDomains: true }).domain;
}

export function alignedDomains(a, b) {
  const left = canonicalDomain(a),
    right = canonicalDomain(b);
  return Boolean(
    left &&
    right &&
    (left === right ||
      (registeredDomain(left) &&
        registeredDomain(left) === registeredDomain(right))),
  );
}
