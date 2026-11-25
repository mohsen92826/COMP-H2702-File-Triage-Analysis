
"""
File Triage & Hash Analysis
COMP H2702 - Scripting for Cybersecurity
Scenario C
"""

import hashlib
import csv
import json
from pathlib import Path
from datetime import datetime


def load_reference_hashes(reference_file):
    """Load valid SHA-256 hashes from the reference CSV."""

    reference_hashes = []

    try:
        with open(reference_file, "r", newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)

            if reader.fieldnames is None or "sha256" not in reader.fieldnames:
                print("Error: Reference CSV must contain a sha256 column.")
                return None

            for row in reader:
                file_hash = row.get("sha256", "").strip().lower()

                if (
                    len(file_hash) == 64
                    and all(char in "0123456789abcdef" for char in file_hash)
                ):
                    reference_hashes.append(file_hash)
                else:
                    print("Warning: Invalid hash entry skipped.")

    except FileNotFoundError:
        print(f"Error: Reference file not found: {reference_file}")
        return None

    except (OSError, UnicodeError, csv.Error) as error:
        print(f"Error reading reference CSV: {error}")
        return None

    if len(reference_hashes) == 0:
        print("Error: No valid reference hashes were found.")
        return None

    return reference_hashes


def calculate_sha256(file_path):
    """Calculate the SHA-256 hash of a file."""

    hash_object = hashlib.sha256()

    with open(file_path, "rb") as file:
        file_data = file.read()
        hash_object.update(file_data)

    return hash_object.hexdigest()


def analyse_folder(folder_path, reference_hashes):
    """Analyse every file in the selected folder."""

    results = []
    errors = []

    folder = Path(folder_path)

    try:
        files = sorted(folder.iterdir())

    except OSError as error:
        print(f"Could not access folder: {error}")
        return results, errors

    for file_path in files:

        if file_path.is_file():

            try:
                file_info = file_path.stat()

                file_hash = calculate_sha256(file_path)

                modified_time = datetime.fromtimestamp(
                    file_info.st_mtime
                ).strftime("%Y-%m-%d %H:%M:%S")

                if file_hash in reference_hashes:
                    status = "KNOWN"
                else:
                    status = "UNKNOWN"

                results.append({
                    "filename": file_path.name,
                    "extension": file_path.suffix,
                    "size_bytes": file_info.st_size,
                    "last_modified": modified_time,
                    "sha256": file_hash,
                    "status": status
                })

            except OSError as error:
                error_message = (
                    f"Could not process {file_path.name}: {error}"
                )
                print(error_message)
                errors.append(error_message)

    return results, errors


def find_duplicates(results):
    """Find files with identical SHA-256 hashes."""

    hash_groups = {}

    for result in results:
        file_hash = result["sha256"]

        if file_hash not in hash_groups:
            hash_groups[file_hash] = []

        hash_groups[file_hash].append(result["filename"])

    duplicates = {}

    for file_hash, filenames in hash_groups.items():

        if len(filenames) > 1:
            duplicates[file_hash] = filenames

    return duplicates


def calculate_summary(results, duplicates):
    """Calculate the analysis summary."""

    known_count = 0
    unknown_count = 0

    for result in results:

        if result["status"] == "KNOWN":
            known_count += 1
        else:
            unknown_count += 1

    summary = {
        "files_analysed": len(results),
        "known_files": known_count,
        "unknown_files": unknown_count,
        "duplicate_groups": len(duplicates)
    }

    return summary


def save_csv_report(results, output_file):
    """Save file results in CSV format."""

    fieldnames = [
        "filename",
        "extension",
        "size_bytes",
        "last_modified",
        "sha256",
        "status"
    ]

    try:
        with open(output_file, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)

        print(f"CSV report saved: {output_file}")

    except (OSError, csv.Error) as error:
        print(f"Could not save CSV report: {error}")


def save_text_report(results, duplicates, summary, errors, output_file):
    """Save a readable text report."""

    try:
        with open(output_file, "w", encoding="utf-8") as file:

            file.write("FILE TRIAGE & HASH ANALYSIS REPORT\n")
            file.write("-----------------------------------\n")

            file.write(f"Files analysed: {summary['files_analysed']}\n")
            file.write(f"Known files: {summary['known_files']}\n")
            file.write(f"Unknown files: {summary['unknown_files']}\n")
            file.write(f"Duplicate groups: {summary['duplicate_groups']}\n")

            file.write("\nFILE DETAILS\n")
            file.write("-----------------------------------\n")

            for result in results:
                file.write(f"Filename: {result['filename']}\n")
                file.write(f"Extension: {result['extension']}\n")
                file.write(f"Size: {result['size_bytes']} bytes\n")
                file.write(f"Last modified: {result['last_modified']}\n")
                file.write(f"SHA-256: {result['sha256']}\n")
                file.write(f"Status: {result['status']}\n")
                file.write("-----------------------------------\n")

            file.write("\nDUPLICATE FILES\n")

            if len(duplicates) == 0:
                file.write("No duplicate files found.\n")
            else:
                for file_hash, filenames in duplicates.items():
                    file.write(f"SHA-256: {file_hash}\n")
                    file.write(f"Files: {', '.join(filenames)}\n")

            file.write("\nFILE PROCESSING ERRORS\n")

            if len(errors) == 0:
                file.write("No file processing errors.\n")
            else:
                for error in errors:
                    file.write(error + "\n")

        print(f"Text report saved: {output_file}")

    except OSError as error:
        print(f"Could not save text report: {error}")


def save_json_report(results, duplicates, summary, errors, output_file):
    """Save analysis results in JSON format."""

    report_data = {
        "summary": summary,
        "files": results,
        "duplicates": duplicates,
        "errors": errors
    }

    try:
        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(report_data, file, indent=4)

        print(f"JSON report saved: {output_file}")

    except (OSError, TypeError) as error:
        print(f"Could not save JSON report: {error}")


def main():
    """Start the file-triage program."""

    print("FILE TRIAGE & HASH ANALYSIS")
    print("===========================")

    folder_path = input(
        "Enter the sample folder path (default: sample_files): "
    ).strip()

    if folder_path == "":
        folder_path = "sample_files"

    reference_file = input(
        "Enter the reference CSV path (default: hashes_reference.csv): "
    ).strip()

    if reference_file == "":
        reference_file = "hashes_reference.csv"

    # Check that the selected folder exists.
    folder = Path(folder_path)

    if not folder.exists() or not folder.is_dir():
        print(f"Error: Sample folder not found: {folder_path}")
        return

    # Load the reference hashes.
    reference_hashes = load_reference_hashes(reference_file)

    if reference_hashes is None:
        print("Analysis stopped because the reference data is invalid.")
        return

    # Analyse files and find duplicates.
    results, errors = analyse_folder(folder_path, reference_hashes)

    duplicates = find_duplicates(results)

    summary = calculate_summary(results, duplicates)

    # Display file results.
    print("\nFILE RESULTS")
    print("------------")

    for result in results:
        print(f"{result['filename']} - {result['status']}")

    print("\nSUMMARY")
    print("-------")
    print(f"Files analysed: {summary['files_analysed']}")
    print(f"Known files: {summary['known_files']}")
    print(f"Unknown files: {summary['unknown_files']}")
    print(f"Duplicate groups: {summary['duplicate_groups']}")
    print(f"File processing errors: {len(errors)}")

    # Create the reports folder.
    reports_folder = Path("reports")

    try:
        reports_folder.mkdir(exist_ok=True)

    except OSError as error:
        print(f"Could not create reports folder: {error}")
        return

    # Save all three reports.
    save_csv_report(
        results,
        reports_folder / "triage_report.csv"
    )

    save_text_report(
        results,
        duplicates,
        summary,
        errors,
        reports_folder / "triage_report.txt"
    )

    save_json_report(
        results,
        duplicates,
        summary,
        errors,
        reports_folder / "triage_report.json"
    )


if __name__ == "__main__":
    main()
