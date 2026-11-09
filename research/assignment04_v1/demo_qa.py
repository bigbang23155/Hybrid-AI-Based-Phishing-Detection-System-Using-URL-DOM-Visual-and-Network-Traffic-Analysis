"""Render only the committed synthetic HTML; no suspicious sites are visited."""
import argparse
import json
from pathlib import Path
from playwright.sync_api import sync_playwright


def run(source, output):
    output.mkdir(parents=True,exist_ok=False)
    checks=[]
    with sync_playwright() as p:
        browser=p.chromium.launch(headless=True)
        for name,width,height in [('desktop',1150,750),('mobile',390,844)]:
            page=browser.new_page(viewport={'width':width,'height':height},device_scale_factor=1)
            external=[]
            def block(route):
                if route.request.url.startswith(('http:','https:')):
                    external.append(route.request.url);route.abort()
                else:route.continue_()
            page.route('**/*',block)
            page.goto(source.resolve().as_uri(),wait_until='load')
            assert page.locator('tr').count()==5
            assert 'Prediction unavailable' in page.locator('body').inner_text()
            assert 'SYNTHETIC SOFTWARE FIXTURE' in page.locator('body').inner_text()
            assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
            assert not external
            page.screenshot(path=str(output/(name+'.png')),full_page=True)
            checks.append({'viewport':name,'width':width,'height':height,'rows':5,'external_requests':0,'document_overflow':False})
            page.close()
        browser.close()
    (output/'checks.json').write_text(json.dumps({'synthetic_only':True,'browser':'chromium','checks':checks},indent=2)+'\n')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    run(Path('results/assignment04/foundation_v1/synthetic_demo.html'),a.output)
