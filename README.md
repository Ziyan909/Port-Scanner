# TCP Port Scanner

A professional, high-performance TCP port scanner written in Python with concurrent scanning, banner grabbing, and service detection.

![GitHub](https://img.shields.io/github/license/Ziyan909/Port-Scanner)
![Python](https://img.shields.io/badge/python-3.6+-blue.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

## Features

✨ **High-Performance Scanning**
- Multi-threaded concurrent scanning using `ThreadPoolExecutor`
- TCP Connect scan methodology for reliable port detection
- Configurable thread pool size (default: 100 threads)
- 1.0 second socket timeout for optimal speed

🔍 **Service Discovery**
- Banner grabbing to identify service versions
- Built-in service port database (FTP, SSH, HTTP, HTTPS, MySQL, etc.)
- Automatic service name detection

🎨 **Professional Output**
- Color-coded results (Green for OPEN, Red for CLOSED, Yellow for FILTERED)
- Clean ASCII art banner
- Formatted table output with PORT | STATE | SERVICE | BANNER
- Optional verbose mode to show all ports
- Results export to .txt file

🛡️ **Robust Error Handling**
- Graceful keyboard interrupt handling (Ctrl+C)
- Hostname to IP resolution
- IP address validation (prevents invalid IP scanning)
- Comprehensive socket error handling

## Installation

### Prerequisites
- Python 3.6 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Ziyan909/Port-Scanner.git
cd Port-Scanner
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Scanning
```bash
python3 scanner.py 192.168.1.1 --ports 1-1024
```

### Scan Specific Ports
```bash
python3 scanner.py example.com --ports 80,443,8080,3306
```

### Advanced Usage
```bash
# Scan with 50 threads and save results
python3 scanner.py 10.0.0.1 --ports 1-65535 --threads 50 --output results.txt

# Show all ports (including closed ones)
python3 scanner.py 192.168.1.1 --ports 1-1024 --verbose

# Combine options
python3 scanner.py target.com --ports 1-10000 --threads 200 --verbose --output scan_results.txt
```

### Command-Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `target` | Target IP address or hostname | Required |
| `--ports` | Port range (1-1024) or list (80,443,8080) | 1-1024 |
| `--threads` | Number of concurrent threads | 100 |
| `--verbose` | Show closed/filtered ports | False |
| `--output` | Save results to text file | None |

## Output Example

```
================================================================================
TCP PORT SCANNER RESULTS
Target: 192.168.1.1
Scan Date: 2026-01-11 10:45:26
================================================================================

PORT     | STATE      | SERVICE         | BANNER                                  
--------------------------------------------------------------------------------
22       | OPEN       | SSH             | OpenSSH_7.4 (protocol 2.0)
80       | OPEN       | HTTP            | Apache/2.4.6 (CentOS)
443      | OPEN       | HTTPS           | nginx/1.14.0
3306     | OPEN       | MySQL           | MySQL 5.7.32

================================================================================
Open Ports: 4
Closed Ports: 1020
Filtered Ports: 0
================================================================================
```

## Performance

- **Average Scanning Speed**: 1000+ ports/second with default settings
- **Full Port Range Scan**: ~65 seconds for all 65535 ports with 100 threads
- **Thread Pool**: Automatically scales performance based on thread count

## Legal Disclaimer

⚠️ **IMPORTANT**: This tool is provided for educational and **authorized security testing purposes only**.

- Unauthorized access to computer systems is **illegal**
- Users are solely responsible for ensuring they have **explicit permission** to scan target systems
- The author assumes **no liability** for misuse or damage caused by this tool
- Use this tool **responsibly and ethically**
- Comply with all applicable laws and regulations

## Security Considerations

- Only scan systems you own or have explicit permission to test
- Be aware of rate limiting on target systems
- Some firewall/IDS systems may block aggressive scanning
- Verbose scanning may generate security alerts

## Troubleshooting

### "Invalid IP address format" error
The IP address must have 4 octets: `192.168.1.1` (valid) vs `10.213.26` (invalid)

### "Cannot resolve hostname" error
The hostname doesn't exist or DNS resolution failed. Verify the target is correct.

### Slow scanning
- Increase thread count: `--threads 200`
- Reduce port range: `--ports 1-1024`
- Check your network connection

### Permission denied
Some ports below 1024 may require elevated privileges:
```bash
sudo python3 scanner.py 192.168.1.1 --ports 1-1024
```

## Development

### Project Structure
```
Port-Scanner/
├── scanner.py          # Main scanner application
├── requirements.txt    # Python dependencies
├── README.md          # Documentation
├── LICENSE            # MIT License
├── .gitignore         # Git ignore rules
└── .github/
    └── workflows/     # CI/CD workflows (optional)
```

### Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Ziyan909** - Security Engineer & Python Developer

## Acknowledgments

- `colorama` library for cross-platform colored output
- Python `concurrent.futures` for efficient thread pooling
- Community feedback and contributions

## Version History

### v1.0.0 (2026-01-11)
- Initial release
- Multi-threaded TCP scanning
- Banner grabbing functionality
- Service detection
- Colored output and table formatting
- File export capability
- IP address validation
- Comprehensive documentation

## Contact & Support

For issues, questions, or suggestions, please open an issue on [GitHub Issues](https://github.com/Ziyan909/Port-Scanner/issues)

---

**Note**: This tool is provided as-is. Always test in a controlled environment first.
