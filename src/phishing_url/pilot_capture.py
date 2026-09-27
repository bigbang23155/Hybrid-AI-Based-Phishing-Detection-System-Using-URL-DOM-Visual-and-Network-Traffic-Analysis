"""Fixed prospective observation pilot; no replacement sampling or model training."""
from __future__ import annotations
import argparse
import asyncio
from collections import defaultdict
from datetime import datetime, timezone
import json
import os
import importlib.metadata
import importlib.resources
from pathlib import Path
import random
import socket
import time
from urllib.parse import urlsplit
from urllib.robotparser import RobotFileParser

import requests

from .legitimate_collection import suitable_url
from .observation import artifact, audit, digest, label_assertion, now, write_json
from .randomness import derive_seed
from .url_cleaning import clean_url, registered_domain


def eligibility(url):
    cleaned=clean_url(url);parts=urlsplit(cleaned)
    if '@' in parts.netloc:raise ValueError('credentials_in_url')
    if parts.port is not None and parts.port not in (80,443):raise ValueError('disallowed_port')
    ok,reason=suitable_url(cleaned,registered_domain(cleaned))
    if not ok:raise ValueError(reason)
    return cleaned


def select_phishing(lines, size, seed, excluded):
    groups=defaultdict(dict);rejected=[]
    for number,raw in enumerate(lines,1):
        try:
            url=eligibility(raw)
            if url in excluded:raise ValueError('cross_source_label_conflict')
            groups[registered_domain(url)].setdefault(url,{'url_raw':raw,'url_clean':url,'source_row':number})
        except ValueError as exc:
            rejected.append({'source_row':number,'url_sha256':digest(raw.encode()),'reason':str(exc)})
    rng=random.Random(derive_seed(seed,'pilot_phishing'))
    chosen=rng.sample(sorted(groups),min(size,len(groups)))
    result=[groups[group][rng.choice(sorted(groups[group]))] for group in chosen]
    return result,rejected,{'valid_domain_groups':len(groups),'unique_eligible_urls':sum(len(g) for g in groups.values())}


def prepare(config,root):
    root.mkdir(parents=True,exist_ok=False);(root/'sources').mkdir()
    write_json(root/'config.json',config)
    session=requests.Session();session.trust_env=False
    repo=config['feed']['repository']
    response=session.get(f'https://api.github.com/repos/{repo}/commits/{config["feed"]["snapshot_commit"]}',timeout=20)
    response.raise_for_status();commit=response.json()
    timestamp=commit['commit']['committer']['date']
    age=(datetime.now(timezone.utc)-datetime.fromisoformat(timestamp.replace('Z','+00:00'))).total_seconds()/3600
    write_json(root/'sources/feed_commit.json',{'sha':commit['sha'],'committed_at':timestamp,'retrieved_at':now(),'age_hours':age})
    if age<-.25 or age>config['max_feed_age_hours']:raise ValueError('feed_commit_outside_freshness_window')
    url=f"https://raw.githubusercontent.com/{repo}/{commit['sha']}/{config['feed']['path']}"
    with session.get(url,timeout=20,stream=True) as response:
        response.raise_for_status();chunks=[];size=0
        for chunk in response.iter_content(65536):
            size+=len(chunk)
            if size>2*1024*1024:raise ValueError('feed_size_limit')
            chunks.append(chunk)
    data=b''.join(chunks);(root/'sources/feed.txt').write_bytes(data)
    controls=config['benign_controls'];control_urls={eligibility(r['url']) for r in controls}
    lines=data.decode('utf-8-sig').splitlines()
    # A direct conflict removes the control too; no substitute controls are added.
    feed_urls=set()
    for raw in lines:
        try:feed_urls.add(eligibility(raw))
        except ValueError:pass
    conflicts=control_urls & feed_urls
    selected,rejected,profile=select_phishing(lines,config['per_stratum'],config['seed'],control_urls)
    candidates=[]
    for c in controls:
        normalized=eligibility(c['url'])
        if normalized in conflicts:continue
        candidates.append({'url_raw':c['url'],'url_clean':normalized,'candidate_class':0,'source':'curated_official_control',
            'evidence':{'organization':c['organization'],'official_reference_url':c['url'],
                        'policy':'purposeful official-site control; assumed benign pending captured-content review'}})
    for c in selected:
        candidates.append({**c,'candidate_class':1,'source':'openphish_community',
            'evidence':{'source_snapshot':'sources/feed.txt','source_sha256':digest(data),'source_row':c['source_row'],
                        'feed_commit':commit['sha'],'feed_committed_at':timestamp,'retrieved_at':now(),
                        'source_url':url,'source_original_label':'phishing','source_verification_time':None}})
    for c in candidates:
        c['candidate_id']=digest((c['source']+'\n'+c['url_clean']).encode())
        c['domain_group']=registered_domain(c['url_clean'])
    random.Random(derive_seed(config['seed'],'pilot_order')).shuffle(candidates)
    write_json(root/'sources/rejected_candidates.json',rejected)
    write_json(root/'plan.json',{'created_at':now(),'protocol_version':config['protocol_version'],'seed':config['seed'],
        'feed_profile':profile,'cross_source_conflict_count':len(conflicts),'config_sha256':digest((root/'config.json').read_bytes()),
        'candidates':candidates,'policy':'Fixed one-pass batch. No replacements, success stopping or formal model training.'})


def robots_allowed(url,proxy,agent):
    parts=urlsplit(url);robots=f'{parts.scheme}://{parts.netloc}/robots.txt'
    session=requests.Session();session.trust_env=False
    try:
        with session.get(robots,headers={'User-Agent':agent},proxies={'http':proxy,'https':proxy},timeout=5,allow_redirects=False,stream=True) as r:
            if r.status_code==404:return True,'robots_404'
            if r.status_code!=200:return False,f'robots_http_{r.status_code}'
            data=b''
            for block in r.iter_content(16384):
                data+=block
                if len(data)>262144:return False,'robots_size_limit'
        parser=RobotFileParser();parser.parse(data.decode('utf-8',errors='replace').splitlines())
        return parser.can_fetch(agent,url),'robots_policy'
    except requests.RequestException as exc:return False,'robots_'+type(exc).__name__


async def preflight(browser,proxy,root):
    result={'non_root':os.geteuid()!=0,'sandbox_requested':True,'private_destinations_blocked':False,'direct_egress_blocked':False}
    def network_checks():
        session=requests.Session();session.trust_env=False
        statuses=[]
        for target in ('http://127.0.0.1/','http://169.254.169.254/','http://10.0.0.1/'):
            response=session.get(target,proxies={'http':proxy},timeout=5)
            statuses.append(response.status_code==403)
        try:
            sock=socket.create_connection(('example.com',443),timeout=2);sock.close();direct=False
        except OSError:direct=True
        return all(statuses),direct
    result['private_destinations_blocked'],result['direct_egress_blocked']=await asyncio.to_thread(network_checks)
    context=await browser.new_context();page=await context.new_page()
    try:
        await page.goto('https://example.com/',timeout=15000,wait_until='domcontentloaded')
        result['public_probe_passed']=page.url.startswith('https://example.com') and 'Example Domain' in await page.title()
    except Exception as exc:result['public_probe_passed']=False;result['error']=type(exc).__name__
    finally:await context.close()
    result['browser_version']=browser.version
    result['passed']=all(result.get(k) is True for k in ('non_root','sandbox_requested','private_destinations_blocked','direct_egress_blocked','public_probe_passed'))
    write_json(root/'preflight.json',result)
    if not result['passed']:raise RuntimeError('isolation_or_connectivity_preflight_failed')


async def capture_one(browser,candidate,config,root,proxy):
    started=now();tick=time.monotonic();oid=digest((candidate['candidate_id']+'\n'+started).encode())
    folder=root/'observations'/oid;folder.mkdir(parents=True)
    record={'schema_version':'observation-v1','observation_id':oid, 'candidate_id':candidate['candidate_id'],
        'candidate_class':candidate['candidate_class'],'source':candidate['source'],
        'url_raw':candidate['url_raw'],'url_clean':candidate['url_clean'],'domain_group':candidate['domain_group'],
        'label':label_assertion(candidate['candidate_class'],candidate['evidence']),
        'started_at':started,'ended_at':started,'status':'failed','reason':None,'final_url':None,
        'http_status':None,'navigation_chain':[],'modalities':{},'capture_duration_ms':0,
        'session':{'browser_version':browser.version,'viewport':config['viewport'],'locale':config['locale'],
                   'timezone_id':config['timezone_id'],'sandbox_enabled':True,'fresh_context':True}}
    events=[];context=None;page=None;request_count=0
    async def work():
        nonlocal context,page,request_count
        allowed,reason=await asyncio.to_thread(robots_allowed,candidate['url_clean'],proxy,config['user_agent'])
        write_json(folder/'robots_decision.json',{'allowed':allowed,'reason':reason,'checked_at':now()})
        if not allowed:record.update(status='skipped',reason=reason);return
        context=await browser.new_context(viewport=config['viewport'],locale=config['locale'],timezone_id=config['timezone_id'],
            user_agent=config['user_agent'],accept_downloads=False,service_workers='block',ignore_https_errors=False)
        await context.route_web_socket('**/*',lambda ws:ws.close())
        page=await context.new_page();page.set_default_timeout(5000)
        context.on('page',lambda other:asyncio.create_task(other.close()) if other!=page else None)
        page.on('dialog',lambda dialog:asyncio.create_task(dialog.dismiss()))
        page.on('download',lambda download:asyncio.create_task(download.cancel()))
        async def route_handler(route):
            nonlocal request_count
            request=route.request;request_count+=1
            try:
                normalized=eligibility(request.url)
                if request.method not in ('GET','HEAD','OPTIONS'):raise ValueError('method_blocked')
                if request_count>config['max_requests_per_observation']:raise ValueError('request_budget')
                if request.is_navigation_request() and request.frame==page.main_frame:
                    record['navigation_chain'].append(request.url)
                    if len(record['navigation_chain'])>6:raise ValueError('navigation_limit')
                    if registered_domain(normalized)!=candidate['domain_group']:raise ValueError('cross_domain_navigation')
                await route.continue_()
            except ValueError as exc:
                events.append({'event':'policy_block','url':request.url,'reason':str(exc),'at':now()})
                await route.abort('blockedbyclient')
        await context.route('**/*',route_handler)
        context.on('request',lambda req:events.append({'event':'request','url':req.url,'method':req.method,'resource_type':req.resource_type,'at':now()}))
        context.on('response',lambda res:events.append({'event':'response','url':res.url,'status':res.status,
            'content_type':res.headers.get('content-type'),'declared_content_length':res.headers.get('content-length'),'at':now()}))
        context.on('requestfailed',lambda req:events.append({'event':'request_failed','url':req.url,'failure':req.failure,'at':now()}))
        response=await page.goto(candidate['url_clean'],timeout=config['max_navigation_ms'],wait_until='domcontentloaded')
        record['http_status']=response.status if response else None
        await page.wait_for_timeout(config['settle_ms'])
        record['final_url']=page.url
        ctype=response.headers.get('content-type','') if response else ''
        html=(await page.content()).encode()
        if len(html)>config['max_dom_bytes']:
            record.update(status='partial',reason='dom_size_limit');return
        (folder/'dom.html').write_bytes(html);record['modalities']['dom']=artifact(root,folder/'dom.html',now())
        await page.screenshot(path=str(folder/'screenshot.png'),full_page=False,timeout=5000)
        record['modalities']['screenshot']=artifact(root,folder/'screenshot.png',now())
        if page.url!=record['final_url']:record.update(status='partial',reason='navigation_during_capture')
        elif response and 200<=response.status<300 and ('text/html' in ctype or 'application/xhtml+xml' in ctype):
            record.update(status='complete',reason=None)
        else:record.update(status='partial',reason=f'non_html_or_http_{record["http_status"]}')
    try:
        await asyncio.wait_for(work(),timeout=config['max_observation_seconds'])
    except Exception as exc:
        record.update(status='failed',reason=type(exc).__name__)
        write_json(folder/'failure.json',{'error_type':type(exc).__name__,'message':str(exc)[:1500]})
    finally:
        if page and not record['final_url']:record['final_url']=page.url
        if context:
            try:await asyncio.wait_for(context.close(),timeout=5)
            except Exception:pass
        write_json(folder/'url.json',{'observation_id':oid,'url_raw':candidate['url_raw'],'url_clean':candidate['url_clean'],
            'final_url':record['final_url'],'navigation_chain':record['navigation_chain'],'captured_at':now()})
        record['modalities']['url']=artifact(root,folder/'url.json',now())
        write_json(folder/'network.json',{'observation_id':oid,'scope':'Browser HTTP events, not PCAP; missing byte counts stay unknown',
            'events':events,'request_count':sum(e['event']=='request' for e in events),
            'policy_blocks':sum(e['event']=='policy_block' for e in events)})
        record['modalities']['network']=artifact(root,folder/'network.json',now())
        record['ended_at']=now();record['capture_duration_ms']=(time.monotonic()-tick)*1000
        write_json(folder/'observation.json',record)
    return record


async def capture(config,root,proxy):
    from playwright.async_api import async_playwright
    plan=json.loads((root/'plan.json').read_text())
    write_json(root/'capture_environment.json',{'created_at':now(),'python':os.sys.version,
        'versions':{name:importlib.metadata.version(name) for name in ('playwright','requests','tldextract','jsonschema')},
        'psl_snapshot_sha256':digest(importlib.resources.files('tldextract').joinpath('.tld_set_snapshot').read_bytes()),
        'private_suffixes':'excluded','proxy':proxy,'browser_sandbox_requested':True})
    async with async_playwright() as engine:
        browser=await engine.chromium.launch(headless=True,chromium_sandbox=True,
            proxy={'server':proxy,'bypass':'<-loopback>'},
            args=['--disable-quic','--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
        try:
            await preflight(browser,proxy,root)
            for candidate in plan['candidates']:
                result=await capture_one(browser,candidate,config,root,proxy)
                # No original URLs in CI logs.
                print(json.dumps({'candidate_id':candidate['candidate_id'],'status':result['status'],'reason':result['reason']}),flush=True)
        finally:await browser.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('prepare','capture','audit','seal'))
    parser.add_argument('--config',type=Path,default=Path('config/observation_pilot_v1.json'))
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--proxy',default='http://guard:8888')
    parser.add_argument('--schema',type=Path,default=Path('schemas/observation_v1.schema.json'))
    args=parser.parse_args(argv);config=json.loads(args.config.read_text())
    if args.command=='prepare':prepare(config,args.root)
    elif args.command=='capture':asyncio.run(capture(config,args.root,args.proxy))
    elif args.command=='audit':
        result=audit(args.root,config,json.loads(args.schema.read_text()))
        print(json.dumps(result,indent=2));return 0 if result['technical_pass'] else 2
    else:
        files={str(p.relative_to(args.root)):digest(p.read_bytes()) for p in sorted(args.root.rglob('*')) if p.is_file() and p.name!='CHECKSUMS.json'}
        write_json(args.root/'CHECKSUMS.json',files)
    return 0


if __name__=='__main__':raise SystemExit(main())
