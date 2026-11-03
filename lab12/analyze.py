"""Static APK inspection. No installation, emulation or execution of APK code."""
import argparse,hashlib,io,json,re,urllib.request,zipfile
from pathlib import Path
from loguru import logger
from lxml import etree
from androguard.core.apk import APK
from androguard.core.dex import DEX
from androguard.core.analysis.analysis import Analysis
from androguard.decompiler.decompiler import DecompilerDAD

def main():
 p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True)
 g.add_argument('--file',type=Path);g.add_argument('--url');p.add_argument('--sha256',required=True)
 p.add_argument('--out',type=Path,required=True);p.add_argument('--decompile',action='store_true');args=p.parse_args()
 logger.remove()
 raw=args.file.read_bytes() if args.file else urllib.request.urlopen(urllib.request.Request(args.url,headers={'User-Agent':'Static-APK-Analysis'}),timeout=60).read()
 sha=hashlib.sha256(raw).hexdigest()
 if sha.lower()!=args.sha256.lower():raise SystemExit('SHA-256 mismatch')
 args.out.mkdir(parents=True,exist_ok=True)
 apk=APK(raw,raw=True);xml=apk.get_android_manifest_xml()
 (args.out/'AndroidManifest.xml').write_bytes(etree.tostring(xml,pretty_print=True,encoding='utf-8',xml_declaration=True))
 result={'sha256':sha,'md5':hashlib.md5(raw).hexdigest(),'size':len(raw),'package':apk.get_package(),'label':apk.get_app_name(),'version_name':apk.get_androidversion_name(),'version_code':apk.get_androidversion_code(),'min_sdk':apk.get_min_sdk_version(),'target_sdk':apk.get_target_sdk_version(),'permissions':sorted(apk.get_permissions()),'activities':sorted(apk.get_activities()),'services':sorted(apk.get_services()),'receivers':sorted(apk.get_receivers()),'providers':sorted(apk.get_providers())}
 (args.out/'metadata.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf8')
 z=zipfile.ZipFile(io.BytesIO(raw));(args.out/'archive.txt').write_text('\n'.join(f'{x.file_size:>10} {x.filename}' for x in z.infolist()),encoding='utf8')
 strings=set();errors=[]
 for name in z.namelist():
  if not re.fullmatch(r'classes\d*\.dex',name):continue
  dex=DEX(z.read(name));strings.update(dex.get_strings())
  if not args.decompile:continue
  # APKProtect leaves some unreadable methods. Record each omission; do not run or repair them.
  for c in dex.get_classes():
   for m in c.get_methods():
    try:list(m.get_instructions())
    except Exception as e:
     errors.append(f'{c.get_name()}->{m.get_name()}{m.get_descriptor()}: {e}')
     if m.get_code():m.get_code().get_bc().cached_instructions=[]
  dx=Analysis(dex);dx.create_xref();dex.set_decompiler(DecompilerDAD(dex,dx))
  dest=args.out/'decompiled';dest.mkdir(exist_ok=True)
  for c in dex.get_classes():
   if not c.get_name().startswith('L'+result['package'].replace('.','/')+'/'):continue
   try:(dest/(c.get_name().strip('L;').replace('/','_')+'.java')).write_text(c.get_source(),encoding='utf8')
   except Exception as e:errors.append(c.get_name()+': '+str(e))
 (args.out/'dex-strings.txt').write_text('\n'.join(x.replace('\x00',r'\u0000') for x in sorted(strings)),encoding='utf8')
 candidates=[s for s in strings if re.search(r'https?://|(?:\d{1,3}\.){3}\d{1,3}|sendTextMessage|ContactsContract|\.apk',s,re.I)]
 (args.out/'string-candidates.txt').write_text('\n'.join(x.replace('\x00',r'\u0000') for x in sorted(candidates)),encoding='utf8')
 (args.out/'invalid-methods.txt').write_text('\n'.join(errors),encoding='utf8')
 print(json.dumps(result,ensure_ascii=False,indent=2))
if __name__=='__main__':
 import sys
 if hasattr(sys.stdout,'reconfigure'):sys.stdout.reconfigure(encoding='utf-8')
 main()
