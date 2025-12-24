"""
DEPRECATED: This file is an outdated copy of the report generator.
An archived copy has been moved to `/archive/report_gen_fix.py`.
Please use `reporting/report_generator.py` for current report generation.
"""

"""
DEPRECATED: Archived report generator.
Use `reporting/report_generator.py` instead.
"""


def info():
    """Return deprecation info for programmatic inspection."""
    return {
        "status": "deprecated",
        "message": "report_gen_fix.py archived. Use reporting/report_generator.py instead.",
        "archive_path": "archive/report_gen_fix.py",
    }


if __name__ == "__main__":
    print(info()["message"])
