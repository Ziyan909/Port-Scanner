#!/usr/bin/env python3
"""
Professional TCP Port Scanner
===============================

A high-performance, concurrent TCP port scanner written in Python with banner grabbing,
service detection, and colored output.

FEATURES:
    - Multi-threaded scanning using ThreadPoolExecutor for high-speed port enumeration
    - TCP Connect scan methodology for reliable port status detection
    - Banner grabbing to identify service versions and running software
    - Color-coded output (Green for OPEN, Red for CLOSED, Yellow for FILTERED)
    - Flexible port range specification (ranges or comma-separated lists)
    - Configurable thread pool size for optimal performance
    - Graceful error handling and keyboard interrupt support
    - Professional ASCII art banner and formatted table output

USAGE:
    python3 scanner.py <target> --ports 1-1024 --threads 100 --verbose

LEGAL DISCLAIMER:
    This tool is provided for educational and authorized security testing purposes only.
    Unauthorized access to computer systems is illegal. Users are solely responsible for
    ensuring they have explicit permission to scan target systems. The author assumes no
    liability for misuse or damage caused by this tool. Use responsibly and ethically.

Author: Security Engineer
Version: 1.0.0
"""

import socket
import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Dict
import time
from colorama import init, Fore, Style

# Initialize colorama for cross-platform colored terminal output
init(autoreset=True)

# ANSI Art Banner
BANNER = f"""
{Fore.GREEN}
╔═══════════════════════════════════════════════════════════════╗
║                  TCP PORT SCANNER v1.0                        ║
║                 Professional Security Tool                    ║
║                                                               ║
║   "Knowledge is power, but responsibility is paramount"      ║
╚═══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""

# Common service ports for quick identification
SERVICE_PORTS: Dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9000: "SonarQube",
}


def parse_arguments() -> argparse.Namespace:
    """
    Parse and validate command-line arguments.
    
    Returns:
        argparse.Namespace: Parsed arguments
    """
    parser = argparse.ArgumentParser(
        description="Professional TCP Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 scanner.py 192.168.1.1 --ports 1-1024
  python3 scanner.py example.com --ports 80,443,8080 --threads 50 --verbose
  python3 scanner.py 10.0.0.1 --ports 1-65535 --threads 200
        """
    )
    
    parser.add_argument(
        "target",
        help="Target IP address or hostname to scan"
    )
    
    parser.add_argument(
        "--ports",
        default="1-1024",
        help="Ports to scan (range: 1-1024 or list: 80,443,8080). Default: 1-1024"
    )
    
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Number of concurrent threads. Default: 100"
    )
    
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show closed/filtered ports in output"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Save results to a text file (e.g., --output results.txt)"
    )
    
    return parser.parse_args()


def parse_ports(port_string: str) -> List[int]:
    """
    Parse port specification into a list of port numbers.
    
    Supports:
        - Range: "1-1024"
        - List: "80,443,8080"
        - Mixed: "22,80,443,8000-8100"
    
    Args:
        port_string: Port specification string
        
    Returns:
        List of valid port numbers
        
    Raises:
        ValueError: If port string is invalid or ports are out of range
    """
    ports = set()
    
    try:
        for part in port_string.split(","):
            part = part.strip()
            
            if "-" in part:
                # Handle range
                start, end = part.split("-")
                start, end = int(start.strip()), int(end.strip())
                
                if not (1 <= start <= 65535) or not (1 <= end <= 65535):
                    raise ValueError(f"Ports must be between 1 and 65535")
                
                if start > end:
                    start, end = end, start
                    
                ports.update(range(start, end + 1))
            else:
                # Handle single port
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port {port} out of valid range (1-65535)")
                ports.add(port)
        
        return sorted(list(ports))
    
    except ValueError as e:
        raise ValueError(f"Invalid port specification: {e}")


def validate_ip_address(ip_string: str) -> bool:
    """
    Validate IP address format (basic check).
    
    Args:
        ip_string: IP address string to validate
        
    Returns:
        True if valid IP format, False otherwise
    """
    parts = ip_string.split('.')
    
    # Must have exactly 4 octets
    if len(parts) != 4:
        return False
    
    # Each octet must be a valid number between 0-255
    for part in parts:
        try:
            num = int(part)
            if not (0 <= num <= 255):
                return False
        except ValueError:
            return False
    
    return True


def resolve_hostname(target: str) -> str:
    """
    Resolve hostname to IP address.
    
    Args:
        target: Hostname or IP address
        
    Returns:
        IP address string
        
    Raises:
        socket.gaierror: If hostname cannot be resolved
    """
    # First check if it looks like an IP address
    if '.' in target and all(c.isdigit() or c == '.' for c in target):
        if not validate_ip_address(target):
            print(f"{Fore.RED}[ERROR] Invalid IP address format: '{target}'{Style.RESET_ALL}")
            sys.exit(1)
    
    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror as e:
        print(f"{Fore.RED}[ERROR] Cannot resolve hostname '{target}': {e}{Style.RESET_ALL}")
        sys.exit(1)


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Attempt to grab banner information from an open port.
    
    Args:
        host: Target IP address
        port: Target port number
        timeout: Socket timeout in seconds
        
    Returns:
        Banner string or empty string if unsuccessful
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else ""
        except socket.timeout:
            return ""
        finally:
            sock.close()
            
    except (socket.timeout, socket.error, OSError):
        return ""


def get_service_name(port: int) -> str:
    """
    Get service name for a given port.
    
    Args:
        port: Port number
        
    Returns:
        Service name or "Unknown"
    """
    return SERVICE_PORTS.get(port, "Unknown")


def scan_port(host: str, port: int, timeout: float = 1.0) -> Tuple[int, str, str]:
    """
    Scan a single port and attempt to identify the service.
    
    Args:
        host: Target IP address
        port: Target port number
        timeout: Socket timeout in seconds
        
    Returns:
        Tuple of (port, state, banner) where state is "OPEN", "CLOSED", or "FILTERED"
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            # Port is OPEN - attempt banner grab
            banner = grab_banner(host, port, timeout=0.5)
            return (port, "OPEN", banner)
        else:
            # Port is not open
            return (port, "CLOSED", "")
            
    except socket.timeout:
        return (port, "FILTERED", "")
    except socket.error:
        return (port, "FILTERED", "")
    except Exception:
        return (port, "FILTERED", "")


def format_banner(banner: str, max_length: int = 50) -> str:
    """
    Format banner for table display.
    
    Args:
        banner: Raw banner string
        max_length: Maximum length before truncation
        
    Returns:
        Formatted banner string
    """
    if not banner:
        return "-"
    
    # Remove newlines and excessive whitespace
    banner = " ".join(banner.split())
    
    # Truncate if too long
    if len(banner) > max_length:
        banner = banner[:max_length - 3] + "..."
    
    return banner


def save_results_to_file(results: List[Tuple[int, str, str]], target: str, filename: str, verbose: bool = False):
    """
    Save scan results to a text file.
    
    Args:
        results: List of (port, state, banner) tuples
        target: Target host that was scanned
        filename: Output filename
        verbose: Whether to include closed ports
    """
    try:
        with open(filename, 'w') as f:
            # Write header
            f.write("=" * 80 + "\n")
            f.write(f"TCP PORT SCANNER RESULTS\n")
            f.write(f"Target: {target}\n")
            f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Write table header
            header = f"{'PORT':<8} | {'STATE':<10} | {'SERVICE':<15} | {'BANNER':<40}\n"
            f.write(header)
            f.write("-" * 80 + "\n")
            
            # Filter results
            open_ports = [r for r in results if r[1] == "OPEN"]
            closed_ports = [r for r in results if r[1] == "CLOSED"]
            filtered_ports = [r for r in results if r[1] == "FILTERED"]
            
            # Write OPEN ports
            for port, state, banner in open_ports:
                service = get_service_name(port)
                banner_str = format_banner(banner, 35)
                line = f"{port:<8} | {state:<10} | {service:<15} | {banner_str:<40}\n"
                f.write(line)
            
            # Write CLOSED ports if verbose
            if verbose:
                for port, state, banner in closed_ports:
                    service = get_service_name(port)
                    line = f"{port:<8} | {state:<10} | {service:<15} | {'-':<40}\n"
                    f.write(line)
            
            # Write FILTERED ports if verbose
            if verbose and filtered_ports:
                for port, state, banner in filtered_ports:
                    service = get_service_name(port)
                    line = f"{port:<8} | {state:<10} | {service:<15} | {'-':<40}\n"
                    f.write(line)
            
            # Write summary
            f.write("\n" + "=" * 80 + "\n")
            f.write(f"Open Ports: {len(open_ports)}\n")
            f.write(f"Closed Ports: {len(closed_ports)}\n")
            f.write(f"Filtered Ports: {len(filtered_ports)}\n")
            f.write("=" * 80 + "\n")
        
        print(f"{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")
    except IOError as e:
        print(f"{Fore.RED}[ERROR] Failed to write to file: {e}{Style.RESET_ALL}")


def print_results(results: List[Tuple[int, str, str]], target: str, verbose: bool = False):
    """
    Print scan results in a formatted table.
    
    Args:
        results: List of (port, state, banner) tuples
        target: Target host that was scanned
        verbose: Whether to show closed ports
    """
    # Filter results
    open_ports = [r for r in results if r[1] == "OPEN"]
    closed_ports = [r for r in results if r[1] == "CLOSED"]
    filtered_ports = [r for r in results if r[1] == "FILTERED"]
    
    # Print header
    print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Scan Results for: {target}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}\n")
    
    # Print table header
    header = f"{'PORT':<8} | {'STATE':<10} | {'SERVICE':<15} | {'BANNER':<40}"
    print(f"{Fore.YELLOW}{header}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'-' * 80}{Style.RESET_ALL}")
    
    # Print OPEN ports
    for port, state, banner in open_ports:
        service = get_service_name(port)
        banner_str = format_banner(banner, 35)
        line = f"{port:<8} | {Fore.GREEN}{state:<10}{Style.RESET_ALL} | {service:<15} | {banner_str:<40}"
        print(line)
    
    # Print CLOSED ports if verbose
    if verbose:
        for port, state, banner in closed_ports:
            service = get_service_name(port)
            line = f"{port:<8} | {Fore.RED}{state:<10}{Style.RESET_ALL} | {service:<15} | {'-':<40}"
            print(line)
    
    # Print FILTERED ports if verbose
    if verbose and filtered_ports:
        for port, state, banner in filtered_ports:
            service = get_service_name(port)
            line = f"{port:<8} | {Fore.YELLOW}{state:<10}{Style.RESET_ALL} | {service:<15} | {'-':<40}"
            print(line)
    
    # Print summary
    print(f"\n{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Open Ports: {len(open_ports)}{Style.RESET_ALL}")
    print(f"{Fore.RED}Closed Ports: {len(closed_ports)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Filtered Ports: {len(filtered_ports)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 80}\n{Style.RESET_ALL}")


def main():
    """Main execution function."""
    # Print banner
    print(BANNER)
    
    try:
        # Parse arguments
        args = parse_arguments()
        
        # Validate and resolve target
        print(f"{Fore.CYAN}[*] Resolving target hostname...{Style.RESET_ALL}")
        target_ip = resolve_hostname(args.target)
        print(f"{Fore.GREEN}[+] Target IP: {target_ip}{Style.RESET_ALL}\n")
        
        # Parse ports
        print(f"{Fore.CYAN}[*] Parsing port specification...{Style.RESET_ALL}")
        ports = parse_ports(args.ports)
        print(f"{Fore.GREEN}[+] Ports to scan: {len(ports)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Port range: {min(ports)}-{max(ports)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Threads: {args.threads}{Style.RESET_ALL}\n")
        
        # Validate thread count
        if args.threads < 1:
            print(f"{Fore.RED}[ERROR] Thread count must be at least 1{Style.RESET_ALL}")
            sys.exit(1)
        
        # Perform scan
        print(f"{Fore.CYAN}[*] Starting scan...{Style.RESET_ALL}\n")
        start_time = time.time()
        results = []
        
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            # Submit all scan jobs
            futures = {
                executor.submit(scan_port, target_ip, port): port 
                for port in ports
            }
            
            # Process completed scans
            completed = 0
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                completed += 1
                
                # Show progress
                if result[1] == "OPEN":
                    print(f"{Fore.GREEN}[+] Port {result[0]}: OPEN{Style.RESET_ALL}")
                elif args.verbose and result[1] == "CLOSED":
                    print(f"{Fore.RED}[-] Port {result[0]}: CLOSED{Style.RESET_ALL}")
        
        # Calculate elapsed time
        elapsed_time = time.time() - start_time
        
        # Sort results by port number
        results.sort(key=lambda x: x[0])
        
        # Print results
        print_results(results, args.target or target_ip, args.verbose)
        
        # Save results to file if requested
        if args.output:
            save_results_to_file(results, args.target or target_ip, args.output, args.verbose)
        
        # Print timing information
        print(f"{Fore.CYAN}Scan completed in {elapsed_time:.2f} seconds{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Average: {len(ports) / elapsed_time:.0f} ports/second{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}[!] Scan interrupted by user (Ctrl+C){Style.RESET_ALL}\n")
        sys.exit(0)
    except ValueError as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}\n")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] An unexpected error occurred: {e}{Style.RESET_ALL}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
