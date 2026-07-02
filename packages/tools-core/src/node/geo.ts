// Node-only (kept out of the package index). Resolves an IP to coarse geolocation + network info
// from the self-hosted GeoLite2 City and ASN databases. Public so the lookup logic is reviewable;
// the .mmdb files + the MaxMind license key stay on the operator's box (paths come from env, this
// code only reads the databases and never sees the license key).
import { open, type Reader, type CityResponse, type AsnResponse } from 'maxmind';

export interface GeoResult {
  continent: string | null;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  postal: string | null;
  latitude: number | null;
  longitude: number | null;
  accuracyKm: number | null;
  timezone: string | null;
  asn: number | null;
  org: string | null;
}

/** Pure mapping from raw GeoLite2 records to our flat shape — unit-tested without a database. */
export function formatGeo(city: CityResponse | null, asn: AsnResponse | null): GeoResult {
  const loc = city?.location;
  const subdivisions = city?.subdivisions;
  const region = subdivisions && subdivisions.length > 0 ? subdivisions[0] : undefined;
  return {
    continent: city?.continent?.names?.en ?? null,
    country: city?.country?.names?.en ?? null,
    countryCode: city?.country?.iso_code ?? null,
    region: region?.names?.en ?? null,
    city: city?.city?.names?.en ?? null,
    postal: city?.postal?.code ?? null,
    latitude: loc?.latitude ?? null,
    longitude: loc?.longitude ?? null,
    accuracyKm: loc?.accuracy_radius ?? null,
    timezone: loc?.time_zone ?? null,
    asn: asn?.autonomous_system_number ?? null,
    org: asn?.autonomous_system_organization ?? null,
  };
}

let cityReader: Reader<CityResponse> | null = null;
let asnReader: Reader<AsnResponse> | null = null;
let loaded = false;
let available = false;

async function ensureLoaded(): Promise<void> {
  if (loaded) return;
  loaded = true;
  try {
    const cityPath = process.env.GEOIP_CITY_DB || '/usr/share/GeoIP/GeoLite2-City.mmdb';
    cityReader = await open<CityResponse>(cityPath);
    // ASN database is optional — geo data still works without the network info.
    const asnPath = process.env.GEOIP_ASN_DB || '/usr/share/GeoIP/GeoLite2-ASN.mmdb';
    try {
      asnReader = await open<AsnResponse>(asnPath);
    } catch {
      asnReader = null;
    }
    available = true;
  } catch {
    // City database missing or unreadable — geolocation is simply unavailable.
    available = false;
  }
}

export async function lookupGeo(ip: string): Promise<GeoResult | null> {
  await ensureLoaded();
  if (!available || !cityReader) return null;
  const city = cityReader.get(ip);
  if (!city) return null;
  const asn = asnReader?.get(ip) ?? null;
  return formatGeo(city, asn);
}
