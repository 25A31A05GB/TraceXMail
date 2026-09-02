# MaxMind GeoIP Data Directory

Place your MaxMind GeoIP2 or GeoLite2 database files or CSV exports in this directory (`backend/data/maxmind/`).

## Supported Files & Formats:
1. **CSV Format**:
   - `GeoLite2-City-Blocks-IPv4.csv` / `GeoLite2-City-Blocks-IPv6.csv`
   - `GeoLite2-City-Locations-en.csv`
   - `GeoLite2-ASN-Blocks-IPv4.csv` / `GeoLite2-ASN-Blocks-IPv6.csv`
2. **Binary MMDB Format**:
   - `GeoLite2-City.mmdb`
   - `GeoLite2-ASN.mmdb`

When any of these files are present in `backend/data/maxmind/`, the TraceXMail forensic backend will automatically parse and query local MaxMind databases for high-precision offline IP geolocation and ASN identification without needing external API calls.
