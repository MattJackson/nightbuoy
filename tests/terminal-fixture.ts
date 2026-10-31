// Synthetic-test terminal harness; never pass real credentials into its JSON process argument.
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
export async function terminalFixture(bin:string,args:string[],options:{passwords?:{prompt:string;value:string}[];actions?:{after?:string;file?:string;keys:string}[]}={}){
 const script=`import os,pty,sys,select,time,fcntl,termios,struct,json,re,base64
s=json.loads(sys.argv[1]);pid,fd=pty.fork()
if pid==0: os.execv(s['bin'],[s['bin']]+s['args'])
fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',35,140,0,0))
out=b'';deadline=time.time()+40;password=0;action=0;done=False;status=None
try:
 while time.time()<deadline:
  if select.select([fd],[],[],0.1)[0]:
   try: chunk=os.read(fd,65536)
   except OSError: chunk=b''
   out+=chunk
   if b'\\x1b[6n' in chunk: os.write(fd,b'\\x1b[1;1R')
   if b'\\x1b[?u' in chunk: os.write(fd,b'\\x1b[?0u')
  plain=re.sub(rb'\\x1b\\[[0-?]*[ -/]*[@-~]',b'',out).replace(b' ',b'')
  if password<len(s['passwords']) and s['passwords'][password]['prompt'].replace(' ','').encode() in plain:
   os.write(fd,s['passwords'][password]['value'].encode()+b'\\n');password+=1
  if action<len(s['actions']):
   a=s['actions'][action]
   if (not a.get('after') or a['after'].replace(' ','').encode() in plain) and (not a.get('file') or (os.path.exists(a['file']) and os.path.getsize(a['file'])>0)):
    os.write(fd,base64.b64decode(a['keys']));action+=1
  child,status=os.waitpid(pid,os.WNOHANG)
  if child: done=True;break
 else: raise Exception('terminal timed out: '+repr(plain[-4500:]))
 assert os.waitstatus_to_exitcode(status)==0,'terminal failed: '+repr(plain[-4500:])
 assert password==len(s['passwords']) and action==len(s['actions']),'terminal did not execute scripted interactions'
 print('terminal interactions passed')
finally:
 if not done:
  try: os.kill(pid,15);os.waitpid(pid,0)
  except ProcessLookupError: pass
 os.close(fd)`;
 const spec={bin,args,passwords:options.passwords??[],actions:(options.actions??[]).map(a=>({...a,keys:Buffer.from(a.keys).toString('base64')}))};
 return promisify(execFile)('python3',['-c',script,JSON.stringify(spec)],{env:{...process.env,NIGHTBUOY_TESTING:'1'},timeout:45000});
}
