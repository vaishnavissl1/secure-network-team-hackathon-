"""Apply the project pages to the local licensed Estate template and build offline static routes."""
import argparse
from pathlib import Path
import shutil
import subprocess
import os

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument("template",type=Path,help="Estate nextjs directory containing package.json")
project=parser.parse_args().template.resolve()
if not (project/"public/hero-image.png").is_file() or not (project/"package-lock.json").is_file():
    parser.error("Expected the Estate Next.js project directory")
overlay=root/"ui/overlay"
backup=project.parent/"shield-wall-original-files"
for src in overlay.rglob("*"):
    if src.is_file():
        rel=src.relative_to(overlay)
        dest=project/rel
        old=backup/rel
        if dest.exists() and not old.exists():
            old.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(dest,old)
        dest.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(src,dest)
npm="npm.cmd" if os.name=="nt" else "npm"
if not (project/"node_modules/next").exists():
    subprocess.run([npm,"ci","--no-audit","--no-fund"],cwd=project,check=True)
subprocess.run([npm,"run","build","--","--webpack"],cwd=project,check=True,
               env={**os.environ,"NEXT_TELEMETRY_DISABLED":"1"})
out=project/"out"
site=root/"dashboard/site"
for rel in ("index.html","controls","evidence","demo","_next","hero-image.png"):
    src=out/rel
    if src.is_dir():
        shutil.copytree(src,site/rel,dirs_exist_ok=True)
    else:
        site.mkdir(parents=True,exist_ok=True)
        shutil.copy2(src,site/rel)
print("Static evaluator UI:",site)
