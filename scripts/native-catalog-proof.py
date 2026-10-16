#!/usr/bin/env python3
"""Verify immutable Ting 0.3.1 package bytes on the matching native runner."""
import hashlib, io, json, os, pathlib, platform, subprocess, tarfile, tempfile, urllib.request, zipfile

SOURCE = '3eed8bb90c18c43ce1b43d58ce0e2ac46a01e0d2'
ARCHIVE_SHA = '7cdcb96dd1883ab3048201ce2c2ff7d6c48006db0dace33cbefe10f2fca20a84'
TARGETS = {
 'linux-x86_64': ('Linux','x86_64','x86_64-unknown-linux-gnu','af8f47cea20d86587ed7ba43249546b084d20cd921ed00a6a58b25e24b01891e'),
 'linux-aarch64': ('Linux','aarch64','aarch64-unknown-linux-gnu','a2744bc80e551010d526d87d8aec9f86bf011036381a8765795d9a01a837140d'),
 'macos-x86_64': ('Darwin','x86_64','x86_64-apple-darwin','b87b6850439e0cdae4138d7e533cbb3d382d8c70725945e7a5e2c5c1503abc7e'),
 'macos-aarch64': ('Darwin','arm64','aarch64-apple-darwin','3bf4672e0e0616ca7967f1b5180015728b84e5befaf5d2773080559f534a1be8'),
 'windows-x86_64': ('Windows','amd64','x86_64-pc-windows-msvc','6f185f33e1705e73f4e3a7daab92f9b4c8a547ef9514bf07b89467a25b0a9694'),
 'windows-aarch64': ('Windows','arm64','aarch64-pc-windows-msvc','8e4094aa031ce65489024b0eb095e21b260e35313f054d8b57088741351eb013'),
}
def digest(raw):return hashlib.sha256(raw).hexdigest()
def download(url):
 with urllib.request.urlopen(url,timeout=90) as response:return response.read()

def main():
 target=os.environ['NATIVE_TARGET'];system,machine,triple,native_sha=TARGETS[target]
 assert platform.system()==system and platform.machine().lower()==machine
 raw=download('https://apps.teamofsilicons.com/v1/apps/ting/packages/3bb24305-fdef-4eb3-a46f-0baccc0c37b1/download')
 assert digest(raw)==ARCHIVE_SHA
 suffix='.exe' if system=='Windows' else ''
 ext='zip' if system=='Windows' else 'tar.gz'
 upstream=download(f'https://github.com/teamofsilicons/silicon-ting/releases/download/v0.3.1/ting-v0.3.1-{triple}.{ext}')
 assert digest(upstream)==native_sha
 if ext=='zip':
  with zipfile.ZipFile(io.BytesIO(upstream)) as archive:
   original={n:archive.read(n) for n in ['ting.exe','ting-daemon.exe']}
 else:
  with tarfile.open(fileobj=io.BytesIO(upstream),mode='r:gz') as archive:
   original={n:archive.extractfile(n).read() for n in ['ting','ting-daemon']}
 with tempfile.TemporaryDirectory() as directory:
  root=pathlib.Path(directory)
  with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
   manifest=json.load(archive.extractfile('apps.yaml'))
   assert (manifest['app_id'],manifest['version'],manifest['command'])==('ting','0.3.1','ting')
   for name,expected in original.items():
    member=archive.getmember(f'targets/{target}/{name}');assert member.isfile()
    contents=archive.extractfile(member).read();assert contents==expected
    path=root/name;path.write_bytes(contents);path.chmod(0o755)
  env={k:v for k,v in os.environ.items() if not k.startswith(('TING_','SILICON_'))}
  home=root/'home';home.mkdir();env.update(SILICON_HOME=str(home),HOME=str(home),USERPROFILE=str(home))
  results=[]
  for args in [['--help'],['accounts','--json'],['login','status','--json'],['--version']]:
   result=subprocess.run([str(root/('ting'+suffix)),*args],capture_output=True,text=True,env=env,timeout=30)
   assert result.returncode==0,result.stderr
   if args==['--help']:assert result.stdout.strip()
   elif args==['accounts','--json']:
    d=json.loads(result.stdout);assert d['app_id']=='ting' and d['accounts_url']=='https://accounts.teamofsilicons.com' and d['apps_url']=='https://apps.teamofsilicons.com'
   elif args==['login','status','--json']:assert json.loads(result.stdout)['authenticated'] is False
   else:assert json.loads(result.stdout)['version']=='0.3.1'
   results.append(dict(argv=args,exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr))
  report=dict(app_id='ting',version='ting 0.3.1',target=target,source_commit=SOURCE,verifier_commit=os.environ['GITHUB_SHA'],archive='apps-ting-0.3.1.tar.gz',sha256=ARCHIVE_SHA,size=len(raw),runtime=dict(system=platform.system(),machine=platform.machine(),native=True),command_results=results,upstream_archive_sha256=native_sha,binary_sha256=digest((root/('ting'+suffix)).read_bytes()),daemon_sha256=digest((root/('ting-daemon'+suffix)).read_bytes()))
  output=pathlib.Path('proof');output.mkdir(exist_ok=True);(output/f'ting-{target}.json').write_text(json.dumps(report,indent=2)+'\n')
 print(target,'verified')
if __name__=='__main__':main()
