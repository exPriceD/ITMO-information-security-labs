"""Повтор четырёх атак на собственный локальный стенд. Только стандартная библиотека."""
import subprocess, time, urllib.request, urllib.parse, urllib.error, sqlite3, json, re, pathlib, argparse
ROOT=pathlib.Path(__file__).resolve().parent

def request(base,login,password):
 class NoRedirect(urllib.request.HTTPRedirectHandler):
  def redirect_request(self,*args): return None
 opener=urllib.request.build_opener(NoRedirect)
 data=urllib.parse.urlencode({'login':login,'password':password}).encode()
 try:r=opener.open(base+'/login',data,timeout=15)
 except urllib.error.HTTPError as e:r=e
 body=r.read().decode('utf8')
 msg=re.search(r'<div class="result">(.*?)</div>',body,re.S)
 return {'login':login,'password':password,'status':r.code,'message':msg.group(1) if msg else '', 'location':r.headers.get('Location','')}

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--exe',default=str(ROOT/'auditlab.exe'));args=parser.parse_args()
 results={}
 # Новая папка для каждой проверки: исходные учебные базы не меняются.
 stamp=time.strftime('%Y%m%d-%H%M%S');dest=ROOT/'evidence'/stamp;dest.mkdir(parents=True)
 for mode,port in [('vulnerable',8080),('secure',8081)]:
  db=dest/(mode+'.db');log=(dest/(mode+'.log')).open('w')
  proc=subprocess.Popen([args.exe,'-mode',mode,'-addr',f'127.0.0.1:{port}','-db',str(db)],stdout=log,stderr=log)
  try:
   base=f'http://127.0.0.1:{port}'
   for _ in range(100):
    try:urllib.request.urlopen(base,timeout=1);break
    except (OSError,urllib.error.URLError):time.sleep(.1)
   else:raise RuntimeError('Сервер не запустился')
   result={'url':base,'sql':request(base,"admin' -- ",'wrong'),
    'sql_password':request(base,'admin',"' OR '1'='1' -- "),
    'enumeration':[request(base,u,'wrong') for u in ['admin','nobody']]}
   with sqlite3.connect(db) as conn:result['database']=[list(x) for x in conn.execute('SELECT login,password FROM users ORDER BY id')]
   # Используем ровно то значение, которое прочитали из базы.
   result['stolen_value_login']=request(base,'student',result['database'][1][1])
   words=['123456','password','qwerty','111111','letmein','welcome','Study!2026']
   # Для student нужен чистый лимит после проверки чтения базы.
   # Перезапуск сохраняет базу и очищает память счётчика и сессий.
   proc.terminate();proc.wait(timeout=10)
   proc=subprocess.Popen([args.exe,'-mode',mode,'-addr',f'127.0.0.1:{port}','-db',str(db)],stdout=log,stderr=log)
   for _ in range(100):
    try:urllib.request.urlopen(base,timeout=1);break
    except (OSError,urllib.error.URLError):time.sleep(.1)
   result['bruteforce']=[request(base,'student',p) for p in words]
   # Обычный вход admin, его лимит не израсходован.
   result['valid_login']=request(base,'admin','Admin!2026')
   results[mode]=result
  finally:proc.terminate();proc.wait(timeout=10);log.close()
 (dest/'results.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf8')
 (ROOT/'evidence'/'latest.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf8')
 v,s=results['vulnerable'],results['secure']
 assert v['sql']['status']==303 and s['sql']['status']==401
 assert v['sql_password']['status']==303 and s['sql_password']['status']==401
 assert v['stolen_value_login']['status']==303 and s['stolen_value_login']['status']==401
 assert v['enumeration'][0]['message']!=v['enumeration'][1]['message']
 assert s['enumeration'][0]['message']==s['enumeration'][1]['message']
 assert v['bruteforce'][-1]['status']==303
 assert [x['status'] for x in s['bruteforce']]==[401]*5+[429]*2
 assert v['valid_login']['status']==s['valid_login']['status']==303
 print(json.dumps(results,ensure_ascii=False,indent=2));print('PASS: все сценарии до/после совпали с ожиданиями')
if __name__=='__main__':main()
