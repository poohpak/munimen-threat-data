import { parse } from "tldts";

export function canonicalDomain(value) {
  if (typeof value !== "string" || !value || /[\s/@:#?\\\[\]]/.test(value))
    return null;
  try {
    const hostname = new URL(`https://${value}`).hostname.replace(/\.$/, "");
    if (
      !/^[a-z0-9.-]+$/.test(hostname) ||
      hostname
        .split(".")
        .some(
          (label) =>
            !label ||
            label.startsWith("-") ||
            label.endsWith("-") ||
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
