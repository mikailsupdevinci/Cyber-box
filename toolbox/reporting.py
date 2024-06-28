def generate_report(results, report_path):
    with open(report_path, 'w') as report_file:
        report_file.write(results)
    print(f"Report generated at {report_path}")
