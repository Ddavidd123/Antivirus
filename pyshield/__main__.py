import argparse
from pyshield.core.scanner import scan_file, scan_directory

def main():
    parser = argparse.ArgumentParser(description='PyShield Antivirus CLI')
    subparsers = parser.add_subparsers(dest="command", required=True)

    file_parser = subparsers.add_parser('scan-file', help='Scan a single file for malware')
    file_parser.add_argument('path', help='Path to the file to scan')

    dir_parser = subparsers.add_parser('scan-dir', help='Scan a directory for malware')
    dir_parser.add_argument('path', help='Path to the directory to scan')
    dir_parser.add_argument("--max-size-mb", type=int, default=25, help="Max file size to scan")

    dir_parser.add_argument(
        "--ext",
        nargs="*",
        default=None,
        help="Allowed extensions, example: .exe .dll .ps1 .js",
    )

    args = parser.parse_args()

    if args.command == "scan-file":
        result = scan_file(args.path)
        print_file_report(result)
    elif args.command == "scan-dir":
        extensions = set(args.ext) if args.ext else None
        result = scan_directory(
            args.path,
            allowed_extensions=extensions,
            max_file_size_mb=args.max_size_mb,
        )
        print_directory_report(result)

def print_file_report(result):
    print("\n== Pyshield File Scan Report ==")
    print(f"File: {result['file_path']}")
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"SHA-256: {result['hash']}")

    if result["is_malware"]:
        print(f"Threat: DETECTED ({result['malware_name']})")
    else:
        print("Threat: CLEAN")

def print_directory_report(result):
    print("\n== Pyshield Directory Scan Report ==")
    print(f"Directory: {result['directory_path']}")
    print(f"Status: {result['status']}")
    print(f"Message: {result['message']}")
    print(f"Total Files Scanned: {result['total_files']}")
    print(f"Malware Detected: {result['malware_detected']}")
    print(f"Clean Files: {result['clean_files']}")
    print(f"Skipped Files: {result['skipped_files']}")
    print(f"Errors: {result['errors']}")

if __name__ == "__main__":
    main()