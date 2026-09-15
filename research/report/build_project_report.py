"""Build the comprehensive project report from explicitly selected evidence."""
import runpy
import sys
from pathlib import Path

if __name__ == '__main__':
    sys.argv = [__file__, '--project-report']
    runpy.run_path(str(Path(__file__).resolve().parents[1]/'paper/build_paper.py'), run_name='__main__')
