import base64,re,json
from pathlib import Path

def decode(s,offset,context=''):
 b=bytearray(base64.b64decode(s[-2:]+s[2:-2]+s[:2]))
 end=len(b)-1-int(chr(b[-1]));flag=b[end-1]
 size=end-3;key=(int(bytes(b[end-3:end-1]).decode(),16)+offset)&255
 out=bytearray(x^key for x in b[:size])
 if flag==1:
  if not context:raise ValueError('caller context required')
  rev=context[::-1]
  out=bytearray(x^ord(rev[i%len(rev)]) for i,x in enumerate(out))
 return out.decode('utf8')
if __name__=='__main__':
 import sys
 if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
 import argparse
 p=argparse.ArgumentParser(description='Static decoding of strings from Config.<clinit>')
 p.add_argument('source',type=Path,help='DAD-decompiled Config.java')
 p.add_argument('--out',type=Path,default=Path('decoded-config.json'))
 a=p.parse_args();s=a.source.read_text('utf8');rows=[]
 for enc in re.findall(r'Config.getSDPath\("([A-Za-z0-9+/=]+)"\)',s.split('public Config()')[0]):
  plain=decode(enc,113,'Config<clinit>');rows.append({'encoded':enc,'decoded':plain});print(plain)
 a.out.write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding='utf8')
