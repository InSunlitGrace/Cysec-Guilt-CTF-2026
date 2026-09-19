import re, itertools, markdown2

def render(md):
    try:
        return markdown2.markdown(md, safe_mode="escape")
    except Exception:
        return None


raw_tag   = re.compile(r'<\s*(img|svg|iframe|script|a|math|details|video|audio|input|form)\b', re.I)
raw_quote = re.compile(r'"\s*(?:on\w+\s*=|srcdoc\s*=|style\s*=\s*"[^"]*expression|javascript:)', re.I)

def hits(out):
    if out is None: return None
    if raw_tag.search(out):   return "TAG"
    if raw_quote.search(out): return "QUOTE"
    # raw " not preceded by &X; entity, followed by onXxx or JS url
    return None


families = []

specials = ['"', "'", '\\', '`', '&#34;', '&#39;', '&quot;', '&apos;', '\\"', "\\'"]
for q in ('"', "'"):
    for s in specials:
        families.append(f'![x](url {q}a{s}b{q})')          #title
        families.append(f'![a{s}b](url)') #alt
        families.append(f'![x](url{s})') # url
        families.append(f'![x](<url{s}>)') # angle url
        families.append(f'[x](url {q}a{s}b{q})') #linktitle
        families.append(f'[x](<url{s}>)')  #angle link url
        families.append(f'[r]: url {q}a{s}b{q}\n\n[x][r]')  # ref title
        families.append(f'[r]: url{s}\n\n[x][r]')  # ref url

for s in specials + [' ', '\t', '\n']:
    families.append(f'<http://x{s}y>')
    families.append(f'<mailto:x{s}y>')
    families.append(f'<x:y{s}z>')

for inner in ['`"`', '`x"`', '*"*', '**"**', '_"_', '~~"~~']:
    families.append(f'![{inner}](url)')
    families.append(f'![x](url "{inner}")')
    families.append(f'[x](url "{inner}")')

for e in ['&#34;', '&#x22;', '&#0000034;', '&quot;', '&amp;quot;', '&amp;#34;']:
    families.append(f'![x](url "{e}")')
    families.append(f'![{e}](url)')
    families.append(f'![x](url{e})')
    families.append(f'[{e}](url)')

alphabet = ['"', "'", '`', '\\', '&', '<', '>', 'x', ' ']
for n in (1, 2, 3):
    for combo in itertools.product(alphabet, repeat=n):
        s = ''.join(combo)
        families.append(f'![{s}](url)')
        families.append(f'![x](url "{s}")')
        families.append(f'![x](url \'{s}\')')
        families.append(f'![x](url{s})')

print("total payloads:", len(families))

seen = set()
for p in families:
    if p in seen: continue
    seen.add(p)
    out = render(p)
    h = hits(out)
    if h:
        print(f"[{h}] IN : {p!r}")
        print(f"      OUT: {out.strip()[:300]}")