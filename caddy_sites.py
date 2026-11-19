"""The owner's own Caddy sites survive panel updates.

The installer writes /etc/caddy/Caddyfile from its template on every update. Sites the panel does not
manage live in /etc/caddy/sites.d/*.caddy, and extra directives for the proxy's own domain (a redirect of
its front page, for example) in /etc/caddy/proxy.d/*.caddy; the template imports both. Before rewriting,
blocks for hosts the panel does not own are moved from the old Caddyfile into sites.d, so a site added
by hand keeps working after the update.
"""
import re
import time
from pathlib import Path

SITES=Path('/etc/caddy/sites.d')
PROXY=Path('/etc/caddy/proxy.d')
SITES_IMPORT='import /etc/caddy/sites.d/*.caddy'
PROXY_IMPORT='import /etc/caddy/proxy.d/*.caddy'


def items(text):
    """Top-level parts of a Caddyfile: ('block', header, source) or ('line', line, source)."""
    result=[];depth=0;start=0;header_end=None;quote=False;comment=False;i=0
    while i<len(text):
        c=text[i]
        if comment:
            if c=='\n':comment=False
        elif quote:
            if c=='\\':i+=1
            elif c=='"':quote=False
        elif c=='"':quote=True
        elif c=='#' and (i==0 or text[i-1] in ' \t\n'):comment=True
        elif c=='{' and text[i+1:i+2]=='$':
            # An environment placeholder such as {$SITE} is part of an address, not a block.
            end=text.find('}',i)
            if end<0:raise ValueError('Caddyfile: не закрыта фигурная скобка.')
            i=end
        elif c=='{':
            if depth==0:header_end=i
            depth+=1
        elif c=='}':
            depth-=1
            if depth<0:raise ValueError('Caddyfile: лишняя закрывающая скобка.')
            if depth==0:
                head=text[start:header_end]
                # Loose top-level lines before the block header are items of their own.
                lines=head.split('\n');header=lines.pop().strip()
                for line in lines:
                    if line.strip() and not line.strip().startswith('#'):result.append(('line',line.strip(),line.strip()))
                result.append(('block',header,(header+' '+text[header_end:i+1]).strip()))
                start=i+1
        elif c=='\n' and depth==0:
            line=text[start:i].strip()
            if line and not line.startswith('#'):result.append(('line',line,line))
            start=i+1
        i+=1
    if depth:raise ValueError('Caddyfile: не закрыта фигурная скобка.')
    tail=text[start:].strip()
    if tail and not tail.startswith('#'):result.append(('line',tail,tail))
    return result


def host(token):
    """The host name of one site address ('' for a port-only or catch-all address such as ':80')."""
    token=re.sub(r'^[a-z]+://','',token.strip().lower()).split('/')[0]
    return re.sub(r':\d+$','',token)


def addresses(header):
    return [token for token in re.split(r'[,\s]+',header.strip()) if token]


def hosts(header):
    return {name for name in map(host,addresses(header)) if name}


def custom_sites(text,managed,existing=''):
    """Blocks and top-level lines of an existing Caddyfile that the panel's template does not produce.

    Sites already defined in `existing` (the text of sites.d) are skipped, so a second run never duplicates them."""
    managed={name.lower() for name in managed if name}
    taken=set();lines=set()
    for kind,head,source in items(existing):
        if kind=='block':taken|=hosts(head)
        else:lines.add(head)
    kept=[]
    for kind,head,source in items(text):
        if kind=='block':
            if not head:continue  # global options
            # A port-only or catch-all block (the caddy package's default ':80 { file_server }') is not the
            # owner's site; keeping it would answer http://IP/ with "Caddy works!" and reveal the proxy.
            if not hosts(head):continue
            own=[token for token in addresses(head) if host(token) not in managed]
            if not own or hosts(' '.join(own))&taken:continue
            if len(own)<len(addresses(head)):
                # Mixed header: keep the owner's hosts; the panel's own host is defined by the template.
                source=', '.join(own)+' '+source[len(head):].lstrip()
        elif head in (SITES_IMPORT,PROXY_IMPORT) or head in lines:continue
        kept.append(source)
    return '\n\n'.join(kept)


def preserve(setup,managed,caddyfile=Path('/etc/caddy/Caddyfile'),sites=SITES,proxy=PROXY):
    """Create the include folders and move hand-made sites out of the Caddyfile that is about to be rewritten."""
    setup.directory(sites,mode=0o755);setup.directory(proxy,mode=0o755)
    if not Path(caddyfile).exists():return None
    existing='\n'.join(path.read_text(encoding='utf-8') for path in sorted(Path(sites).glob('*.caddy')))
    kept=custom_sites(Path(caddyfile).read_text(encoding='utf-8'),managed,existing)
    if not kept.strip():return None
    target=Path(sites)/('kept-'+time.strftime('%Y%m%d-%H%M%S')+'.caddy')
    setup.write(target,'# Перенесено из /etc/caddy/Caddyfile при обновлении панели. Свои сайты держи в этой папке.\n'+kept+'\n')
    print('Свои сайты из Caddyfile сохранены: '+str(target))
    return target


def includes():
    return '\n'+SITES_IMPORT+'\n'
