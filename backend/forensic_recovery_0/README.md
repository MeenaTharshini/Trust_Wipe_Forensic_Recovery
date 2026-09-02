# TrustWipe Commercial Forensic Recovery Module

A high-performance, real-time forensic recovery and file carving engine built for enterprise data sanitization verification and evidence acquisition.

## Core Capabilities
- **Signature-Based File Carving**: Dynamic sliding window pattern matcher supporting JPEG, PNG, PDF, ZIP/Office documents, SQLite, MP4, Executable headers.
- **Cryptographic Evidence Verification**: Continuous streaming SHA-256, MD5, and SHA-1 hashing.
- **Data Entropy Analysis**: Calculates Shannon entropy (0.0 to 8.0) to detect encrypted sectors versus raw structures.
- **Chain of Custody**: Cryptographically signed audit trail recording every inspection event.
- **Inter-Process CLI API**: Outputs real-time JSON events for Node.js / React integration.

## Usage via CLI
```bash
# List available target drives
python cli.py --list-drives --json

# Execute scan and carve on target
python cli.py --scan --target "C:\path\to\target" --case "CASE-101" --investigator "Officer Smith" --json
```
