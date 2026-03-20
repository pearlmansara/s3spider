# S3Spider 🕷️

> **MANSPIDER for S3** — Enumerate AWS S3 buckets and scan their contents for sensitive data.

Inspired by [MANSPIDER](https://github.com/blacklanternsecurity/MANSPIDER), S3Spider enumerates all S3 buckets accessible to one or more AWS profiles, then crawls each bucket scanning file contents for secrets, credentials, PII, and other sensitive data using configurable regex patterns.

---

## Features

- 🔍 **Bucket Enumeration** — Lists all buckets accessible to your AWS account(s) and checks read access before scanning
- 👤 **Multi-Profile Support** — Scan across multiple AWS profiles simultaneously with `--profiles`
- 🧵 **Concurrent Scanning** — Threaded object downloads and scans per bucket
- 📄 **Wide File Support** — Scans text, JSON, YAML, XML, CSV, `.env`, config files, Python/JS/Ruby/PHP/SQL code, PDFs, Word docs (.docx), and Excel spreadsheets (.xlsx)
- 🎯 **Pattern Matching** — 20+ built-in regex patterns for AWS keys, API tokens, passwords, PII (SSN, credit cards), private keys, and more
- 🎨 **Rich Console Output** — Color-coded findings with severity highlighting printed in real time
- 📊 **Excel Report** — Automatically generates a `.xlsx` report with a Summary sheet and a color-coded Findings sheet
- 💾 **Optional Download** — Download matched files locally with `--download`
- 🔌 **Extensible** — Add your own patterns via a YAML file with `--patterns-file`

---

## Installation

```bash
cd s3spider
pip install -r requirements.txt
```

### Requirements
- Python 3.10+
- AWS credentials configured in `~/.aws/credentials` or via environment variables

---

## Usage

```
python s3spider.py [options]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--profiles PROFILE [...]` | default profile | AWS profile(s) from `~/.aws/credentials` |
| `--extensions EXT [...]` | all supported | File extensions to scan (e.g. `.env .json .txt`) |
| `--patterns-file FILE` | — | Custom YAML patterns file (merged with built-ins) |
| `--threads N` | `5` | Concurrent threads per bucket |
| `--max-size MB` | `10` | Max file size to download/scan in MB |
| `--download` | off | Download matched files to `./downloads/` |
| `--download-dir DIR` | `./downloads` | Directory to save downloaded files |
| `--output FILE` | auto-timestamped | Excel report output path |
| `--verbose` / `-v` | off | Enable debug logging |
| `--no-banner` | off | Suppress the ASCII banner |

---

## Examples

```bash
# Scan using the default AWS profile
python s3spider.py

# Scan using multiple named profiles
python s3spider.py --profiles dev-readonly prod-readonly staging

# Scan only .env and .json files
python s3spider.py --profiles dev --extensions .env .json

# Scan and download matched files
python s3spider.py --profiles prod --download

# Use custom regex patterns (merged with built-ins)
python s3spider.py --profiles prod --patterns-file custom_patterns.yaml

# Limit to 5 MB files, 10 threads, save report to specific file
python s3spider.py --profiles prod --max-size 5 --threads 10 --output /tmp/report.xlsx
```

---

## Output

### Console
Findings are printed in real time as each file is scanned:

```
  [CRITICAL] AWS Access Key ID  s3://my-bucket/config/app.env  line 4
    AWS_ACCESS_KEY_ID=AKIA4EXAMPLE12345678

  [HIGH] Password in Config  s3://my-bucket/deploy/settings.yaml  line 12
    db_password: s3cr3tPassw0rd!
```

### Excel Report
Two sheets are generated:

- **Summary** — Severity counts + per-bucket breakdown
- **Findings** — Full detail table:

  | Profile | Region | Bucket ARN | S3 File (Key) | S3 URI | Match Type | Severity | Line # | Matched Line |
  |---------|--------|------------|---------------|--------|------------|----------|--------|--------------|

Rows are color-coded by severity:
- 🔴 `CRITICAL` — Light red
- 🟠 `HIGH` — Light orange
- 🟡 `MEDIUM` — Light yellow
- ⚪ `LOW` — Light grey

---

## Built-in Detection Patterns

| Pattern | Severity |
|---------|----------|
| AWS Access Key ID | CRITICAL |
| AWS Secret Access Key | CRITICAL |
| AWS Session Token | CRITICAL |
| Database Connection String | CRITICAL |
| RSA / PEM Private Key | CRITICAL |
| SSH Private Key | CRITICAL |
| PGP Private Key | CRITICAL |
| Credit Card Number | CRITICAL |
| Social Security Number (SSN) | CRITICAL |
| Stripe Secret Key | CRITICAL |
| Generic API Key / Token | HIGH |
| Bearer Token | HIGH |
| Password in Config | HIGH |
| Slack Token | HIGH |
| GitHub Token | HIGH |
| Google API Key | HIGH |
| Twilio Account SID / Auth Token | HIGH |
| Generic Secret | MEDIUM |
| .env File Pattern | MEDIUM |
| Email Address | LOW |
| IP Address (Private Range) | LOW |
| Hardcoded Username | LOW |

---

## Custom Patterns

Create a YAML file following the same format as `patterns/default.yaml`:

```yaml
patterns:
  - name: My Custom Token
    regex: 'myapp_token_[A-Za-z0-9]{32}'
    severity: high

  - name: Internal IP Range
    regex: '\b172\.16\.\d{1,3}\.\d{1,3}\b'
    severity: medium
```

Then pass it with `--patterns-file my_patterns.yaml`. It will be merged with the built-in patterns.

---

## Supported File Types

### Text / Code (streamed, no temp files)
`.txt` `.log` `.csv` `.env` `.conf` `.config` `.yaml` `.yml` `.json` `.xml` `.ini` `.cfg` `.sh` `.bash` `.zsh` `.py` `.rb` `.js` `.ts` `.php` `.sql` `.md` `.toml` `.properties` `.gradle` `.tf` `.tfvars` `.pem` `.key` `.crt` `.cer` `.pub`

### Binary (parsed in memory)
- **PDF** (`.pdf`) — via `pdfplumber`
- **Word** (`.docx`) — via `python-docx`
- **Excel** (`.xlsx`) — via `openpyxl`

---

## Project Structure

```
s3spider/
├── s3spider.py           # Main CLI entrypoint
├── scanner/
│   ├── __init__.py
│   ├── buckets.py        # Bucket enumeration & access checking
│   ├── crawler.py        # Object listing, streaming & scanning
│   ├── detector.py       # Pattern loading & regex matching
│   ├── parsers.py        # Text extraction (plain text, PDF, DOCX, XLSX)
│   └── reporter.py       # Excel report generation
├── patterns/
│   └── default.yaml      # Built-in sensitive data patterns
├── downloads/            # Downloaded files (when --download is used)
├── requirements.txt
└── README.md
```

---

## AWS Permissions Required

The tool only needs **read** access. The minimum IAM permissions needed are:

```json
{
  "Effect": "Allow",
  "Action": [
    "s3:ListAllMyBuckets",
    "s3:GetBucketLocation",
    "s3:ListBucket",
    "s3:GetObject",
    "sts:GetCallerIdentity"
  ],
  "Resource": "*"
}
```

---

## Disclaimer

This tool is intended for **authorized security assessments and internal auditing only**. Do not use it against AWS accounts you do not own or have explicit written permission to test.
