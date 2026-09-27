"""Versioned robots evidence and uniform visible-content readiness checks."""
from __future__ import annotations
import time
from urllib.parse import urlsplit, urljoin
from urllib.robotparser import RobotFileParser
import requests
from .observation import artifact, now, write_json


def origin(url):
    p=urlsplit(url)
    return p.scheme,p.hostname,p.port or (443 if p.scheme=='https' else 80)


def check_robots(url, proxy, agent, root, folder, max_redirects=3, session=None):
    from .pilot_capture import eligibility
    p=urlsplit(url);current=f'{p.scheme}://{p.netloc}/robots.txt';expected=origin(current)
    session=session or requests.Session();session.trust_env=False
    hops=[];allowed=False;reason='robots_unresolved';deadline=time.monotonic()+12
    body=None;active_hop=None;index=-1
    try:
        for index in range(max_redirects+1):
            body=None;active_hop=None
            remaining=deadline-time.monotonic()
            if remaining<=0:raise TimeoutError('robots total deadline')
            with session.get(current,headers={'User-Agent':agent},proxies={'http':proxy,'https':proxy},
                    timeout=min(4,remaining),allow_redirects=False,stream=True) as response:
                stamp=now();body=bytearray();truncated=False
                hop={'url':current,'http_status':response.status_code,'retrieved_at':stamp,
                    'headers':{k:response.headers.get(k) for k in ('content-type','location','date','x-research-gateway-error-type')}}
                active_hop=hop;hops.append(hop)
                for block in response.iter_content(16384):
                    room=262144-len(body);body.extend(block[:room])
                    if len(block)>room:truncated=True;break
                    if time.monotonic()>deadline:raise TimeoutError('robots body deadline')
                path=folder/f'robots_{index}.txt';path.write_bytes(body)
                hop.update(body=artifact(root,path,now()),truncated=truncated)
                if truncated:reason='robots_size_limit';break
                if response.headers.get('x-research-gateway-error-type'):
                    reason='robots_gateway_'+response.headers['x-research-gateway-error-type'];break
                if response.status_code in (301,302,303,307,308):
                    location=response.headers.get('location')
                    if not location:reason='robots_redirect_without_location';break
                    target=eligibility(urljoin(current,location));hop['redirect_target']=target
                    if origin(target)!=expected:reason='robots_cross_origin_redirect';break
                    if index==max_redirects:reason='robots_redirect_limit';break
                    current=target;continue
                if response.status_code==404:allowed=True;reason='robots_404';break
                if response.status_code!=200:reason=f'robots_http_{response.status_code}';break
                ctype=response.headers.get('content-type','').lower()
                if 'text/html' in ctype or bytes(body).lstrip().lower().startswith((b'<!doctype html',b'<html')):
                    reason='robots_html_instead_of_rules';break
                parser=RobotFileParser();parser.parse(bytes(body).decode('utf-8',errors='replace').splitlines())
                allowed=parser.can_fetch(agent,url);reason='robots_allowed' if allowed else 'robots_disallow';break
    except (requests.RequestException,ValueError,TimeoutError) as exc:
        reason='robots_'+type(exc).__name__
        if body is not None and active_hop is not None:
            path=folder/f'robots_{index}_partial.txt';path.write_bytes(body)
            active_hop.update(body=artifact(root,path,now()),truncated=True,error_type=type(exc).__name__)
        else:hops.append({'url':current,'error_type':type(exc).__name__,'at':now()})
    result={'policy_version':'robots-v2','original_url':url,'allowed':allowed,'reason':reason,'hops':hops,
        'max_redirects':max_redirects,'redirect_scope':'exact origin only','checked_at':now()}
    write_json(folder/'robots_decision.json',result)
    return allowed,reason


VISIBLE_STATE_JS = """() => {
 const w=innerWidth,h=innerHeight;
 const visible=e=>{const s=getComputedStyle(e),r=e.getBoundingClientRect();
   return s.display!=='none'&&s.visibility!=='hidden'&&Number(s.opacity)!==0&&r.width>0&&r.height>0&&r.bottom>0&&r.right>0&&r.top<h&&r.left<w;};
 let chars=0; const walk=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);let n;
 while(n=walk.nextNode()){
   if(!n.parentElement||!visible(n.parentElement)||['SCRIPT','STYLE','NOSCRIPT'].includes(n.parentElement.tagName))continue;
   const range=document.createRange();range.selectNodeContents(n);const r=range.getBoundingClientRect();
   if(r.width>0&&r.height>0&&r.top<h&&r.bottom>0&&r.left<w&&r.right>0)chars+=n.textContent.trim().length;
 }
 const images=[...document.images].filter(e=>visible(e)&&e.complete&&e.naturalWidth>0);
 const areas=images.map(e=>{const r=e.getBoundingClientRect();return Math.max(0,Math.min(w,r.right)-Math.max(0,r.left))*Math.max(0,Math.min(h,r.bottom)-Math.max(0,r.top));});
 return {ready_state:document.readyState,visible_text_chars:chars,loaded_visible_images:images.length,
   largest_visible_image_fraction:Math.max(0,...areas)/(w*h),body_width:document.body.scrollWidth,body_height:document.body.scrollHeight};
}"""


def nonblank(state, config):
    return state['visible_text_chars']>=config['min_visible_text_chars'] or state['largest_visible_image_fraction']>=config['min_image_viewport_fraction']


async def wait_visible(page, config):
    started=time.monotonic();states=[];previous=None;stable=0;passed=False
    while (time.monotonic()-started)*1000<config['max_wait_ms']:
        try:state=await page.evaluate(VISIBLE_STATE_JS)
        except Exception as exc:
            states.append({'at':now(),'error_type':type(exc).__name__});break
        signature=tuple(state[k] for k in ('visible_text_chars','loaded_visible_images','body_width','body_height'))
        stable=stable+1 if signature==previous else 1;previous=signature
        states.append({'at':now(),**state,'consecutive_stable_polls':stable})
        elapsed=(time.monotonic()-started)*1000
        if state['ready_state']=='complete' and nonblank(state,config) and stable>=config['stable_polls'] and elapsed>=config['min_wait_ms']:
            passed=True;break
        await page.wait_for_timeout(config['poll_ms'])
    return {'policy_version':'visible-readiness-v2','passed':passed,'elapsed_ms':(time.monotonic()-started)*1000,
        'reason':'stable_visible_content' if passed else 'visible_content_not_ready_within_budget',
        'thresholds':config,'states':states,'scope':'render availability only; not a content or safety label'}
