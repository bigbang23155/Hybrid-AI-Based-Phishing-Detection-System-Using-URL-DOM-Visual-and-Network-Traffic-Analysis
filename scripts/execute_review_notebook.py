"""Execute the reader notebook in the cloud and retain its actual outputs."""
import argparse
from pathlib import Path
import nbformat
from nbclient import NotebookClient
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
root=Path.cwd();n=nbformat.read(root/'notebooks/assignment03_development_review.ipynb',as_version=4)
NotebookClient(n,timeout=120,kernel_name='python3',resources={'metadata':{'path':str(root)}}).execute()
nbformat.validate(n);nbformat.write(n,a.output)
print('Notebook executed:',sum(c.cell_type=='code' for c in n.cells),'code cells')
