#!/usr/bin/env python3
"""Publish a verified native ARM64 Ting build through S3 + SSM, with rollback."""
import argparse,hashlib,json,pathlib,shlex,subprocess,tarfile,tempfile,time
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',type=pathlib.Path,default=pathlib.Path('target/aarch64-unknown-linux-gnu/release/ting-server'))
p.add_argument('--caddy',type=pathlib.Path,required=True)
p.add_argument('--region',default='us-east-1')
a=p.parse_args()
def aws(*parts):return subprocess.check_output(['aws','--region',a.region,*parts],text=True)
binary=a.binary.read_bytes()
if binary[:4]!=b'\x7fELF' or binary[18:20]!=b'\xb7\x00':raise SystemExit('Expected Linux ARM64 ELF binary')
stack=json.loads(aws('cloudformation','describe-stacks','--stack-name','silicon-ting-production'))['Stacks'][0]
o={x['OutputKey']:x['OutputValue'] for x in stack['Outputs']}
base=pathlib.Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as tmp:
 archive=pathlib.Path(tmp)/'release.tar.gz'
 with tarfile.open(archive,'w:gz') as t:
  t.add(a.binary,arcname='ting-server');t.add(a.caddy,arcname='caddy')
  for name in ('install.sh','ting-server.service','Caddyfile','caddy.service','backup.py','ting-backup.service','ting-backup.timer'):t.add(base/name,arcname=name)
 checksum=hashlib.sha256(archive.read_bytes()).hexdigest();release=checksum[:16];uri=f"s3://{o['ArtifactBucket']}/releases/{release}.tar.gz";remote='/opt/ting/releases/'+release
 aws('s3','cp',str(archive),uri,'--sse','AES256','--only-show-errors')
 command='\n'.join(['set -e','umask 022',f'mkdir -p {remote}',f'aws s3 cp {shlex.quote(uri)} {remote}.tgz --region {a.region} --only-show-errors',f"echo '{checksum}  {remote}.tgz' | sha256sum -c -",f'tar -xzf {remote}.tgz -C {remote}',f'chmod 755 {remote}/ting-server {remote}/caddy',f'bash {remote}/install.sh {remote} {a.region}'])
 request=pathlib.Path(tmp)/'request.json';request.write_text(json.dumps({'DocumentName':'AWS-RunShellScript','InstanceIds':[o['InstanceId']],'Parameters':{'commands':[command]},'Comment':'Silicon Ting release '+release}))
 cid=json.loads(aws('ssm','send-command','--cli-input-json','file://'+str(request)))['Command']['CommandId']
print(json.dumps({'release':release,'instance':o['InstanceId'],'command_id':cid}),flush=True)
for _ in range(150):
 time.sleep(2)
 result=json.loads(aws('ssm','get-command-invocation','--command-id',cid,'--instance-id',o['InstanceId']))
 if result['Status'] in ('Pending','InProgress','Delayed'):continue
 print(result['Status'],result['StandardOutputContent'],result['StandardErrorContent'])
 raise SystemExit(0 if result['Status']=='Success' else 1)
raise SystemExit('Still running. Inspect the command ID before retrying.')
