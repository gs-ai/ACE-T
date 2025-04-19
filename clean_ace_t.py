import os
import shutil
import glob

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "output")
DB_PATH = os.path.join(PROJECT_ROOT, "test.db")
ALEMBIC_VERSIONS = os.path.join(PROJECT_ROOT, "alembic", "versions")

# Remove all log files and per-alert JSONs
if os.path.exists(OUTPUT_DIR):
    for f in glob.glob(os.path.join(OUTPUT_DIR, "*.csv")) + \
             glob.glob(os.path.join(OUTPUT_DIR, "*.json")):
        os.remove(f)
    print(f"[+] Cleaned logs and JSONs in {OUTPUT_DIR}")
else:
    print(f"[!] Output directory {OUTPUT_DIR} does not exist.")

# Remove database file
def remove_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
        print(f"[+] Removed database: {DB_PATH}")
    else:
        print(f"[!] Database file {DB_PATH} does not exist.")

remove_db()

# Optionally clean Alembic migration versions (uncomment if you want to reset migrations)
# if os.path.exists(ALEMBIC_VERSIONS):
#     for f in os.listdir(ALEMBIC_VERSIONS):
#         os.remove(os.path.join(ALEMBIC_VERSIONS, f))
#     print(f"[+] Cleaned Alembic migration versions in {ALEMBIC_VERSIONS}")

# Remove __pycache__ folders recursively
def remove_pycache(root):
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            if d == "__pycache__":
                shutil.rmtree(os.path.join(dirpath, d))
                print(f"[+] Removed {os.path.join(dirpath, d)}")

remove_pycache(PROJECT_ROOT)

print("[+] ACE-T workspace is clean.")
