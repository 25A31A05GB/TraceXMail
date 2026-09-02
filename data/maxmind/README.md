# MaxMind GeoLite2 Data Directory

This directory contains both CSV datasets and binary MaxMind database representations for TraceXMail IP Forensics.

## Contents
- `GeoLite2-City-Blocks-IPv4.csv`: IPv4 CIDR to Geoname ID mappings with latitude/longitude/accuracy.
- `GeoLite2-City-Locations-en.csv`: Geoname ID to City, Region, Country, and Continent mappings.
- `GeoLite2-ASN-Blocks-IPv4.csv`: IPv4 CIDR to Autonomous System Number (ASN) and Organization mappings.

TraceXMail automatically indexes these CSV records or utilizes binary `.mmdb` files when available for sub-millisecond offline forensic queries.
