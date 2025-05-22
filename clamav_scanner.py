# clamav_scanner.py
import subprocess

def scan_with_clamav(filepath):
    try:
        result = subprocess.run(
            ['clamscan', filepath],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        output = result.stdout
        infected = "Infected files: 1" in output
        return {
            "status": "infected" if infected else "clean",
            "details": output
        }
    except Exception as e:
        return {
            "status": "error",
            "details": str(e)
        }
