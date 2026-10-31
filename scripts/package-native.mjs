// Native package rehearsal only. No signing, store upload, tag or release publication.
import {mkdir,cp,writeFile,readFile,readdir,rm,chmod} from 'node:fs/promises';
import {existsSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const target=process.argv[2];
const targets={
 'x86_64-unknown-linux-gnu':{os:'linux',deb:'amd64',rpm:'x86_64',arch:'x86_64'},
 'aarch64-unknown-linux-gnu':{os:'linux',deb:'arm64',rpm:'aarch64',arch:'aarch64'},
 'aarch64-apple-darwin':{os:'darwin'},'x86_64-apple-darwin':{os:'darwin'},
 'x86_64-pc-windows-msvc':{os:'win32',inno:'x64compatible'},
 'aarch64-pc-windows-msvc':{os:'win32',inno:'arm64'},
};
const spec=targets[target];if(!spec||spec.os!==process.platform)throw Error('Pass a supported native Rust target for this host.');
const version=JSON.parse(await readFile('package.json','utf8')).version;
if(!/^\d+\.\d+\.\d+$/.test(version))throw Error('Invalid package version');
const out=resolve('dist',target),name=`nightbuoy-${version}-${target}`,stage=join(out,name);
const outputs=[];function artifact(file){outputs.push(file);return join(out,file);}
await mkdir(out,{recursive:true});await rm(stage,{recursive:true,force:true});await mkdir(stage);
const binary=resolve('target',target,'release','nightbuoy'+(process.platform==='win32'?'.exe':''));
function run(command,args,options={}){const r=spawnSync(command,args,{stdio:'inherit',...options});if(r.error)throw r.error;if(r.status!==0)throw Error(`${command} exited ${r.status}`);}
async function text(path,value){await mkdir(resolve(path,'..'),{recursive:true});await writeFile(path,value);}
async function executable(source,dest){await cp(source,dest);await chmod(dest,0o755);}
for(const file of ['LICENSE','THIRD_PARTY_NOTICES.md','README.md'])await cp(file,join(stage,file));
if(process.platform==='win32'){
 await cp(binary,join(stage,'nightbuoy.com'));
 await cp(resolve('target',target,'release','nightbuoy-gui.exe'),join(stage,'nightbuoy.exe'));
 run('powershell.exe',['-NoProfile','-Command','Compress-Archive -LiteralPath $env:NB_STAGE -DestinationPath $env:NB_ZIP -Force'],{env:{...process.env,NB_STAGE:stage,NB_ZIP:artifact(name+'.zip')}});
 const iscc=[7,6].map(v=>join(process.env['ProgramFiles(x86)']||'C:\\Program Files (x86)',`Inno Setup ${v}`,'ISCC.exe')).find(existsSync);
 if(!iscc)throw Error('Inno Setup compiler is required for the installer rehearsal.');
 run(iscc,[`/DVersion=${version}`,`/DTargetArch=${spec.inno}`,`/DStage=${stage}`,`/DOutput=${out}`,resolve('packaging/windows.iss')]);
 artifact(`nightbuoy-${version}-${spec.inno}-setup.exe`);
}else if(process.platform==='darwin'){
 await executable(binary,join(stage,'nightbuoy'));
 const app=join(stage,'NightBuoy.app'),contents=join(app,'Contents');
 await mkdir(join(contents,'MacOS'),{recursive:true});await executable(binary,join(contents,'MacOS','nightbuoy'));
 await text(join(contents,'Info.plist'),`<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleExecutable</key><string>nightbuoy</string><key>CFBundleIdentifier</key><string>org.nightbuoy.app</string><key>CFBundleName</key><string>NightBuoy</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>${version}</string><key>CFBundleVersion</key><string>${version}</string><key>NSHighResolutionCapable</key><true/></dict></plist>`);
 // Ad-hoc signing makes the bundle internally consistent; this is not Developer ID/notarization.
 run('codesign',['--force','--sign','-','--timestamp=none',app]);run('codesign',['--verify','--strict',app]);
 run('ditto',['-c','-k','--sequesterRsrc','--keepParent',stage,artifact(name+'.zip')]);
 const dmgRoot=join(out,'dmg-root');await rm(dmgRoot,{recursive:true,force:true});await mkdir(dmgRoot);await cp(app,join(dmgRoot,'NightBuoy.app'),{recursive:true});
 run('ln',['-s','/Applications',join(dmgRoot,'Applications')]);
 run('hdiutil',['create','-ov','-format','UDZO','-volname','NightBuoy','-srcfolder',dmgRoot,artifact(name+'.dmg')]);
 run('pkgbuild',['--component',app,'--install-location','/Applications','--identifier','org.nightbuoy.app','--version',version,artifact(name+'.pkg')]);
 await rm(dmgRoot,{recursive:true,force:true});
}else{
 await executable(binary,join(stage,'nightbuoy'));run('tar',['-czf',artifact(name+'.tar.gz'),'-C',out,name]);
 const root=join(out,'linux-root');await rm(root,{recursive:true,force:true});
 await mkdir(join(root,'usr/bin'),{recursive:true});await executable(binary,join(root,'usr/bin/nightbuoy'));
 await mkdir(join(root,'usr/share/applications'),{recursive:true});await cp('packaging/nightbuoy.desktop',join(root,'usr/share/applications/nightbuoy.desktop'));
 await mkdir(join(root,'usr/share/icons/hicolor/scalable/apps'),{recursive:true});await cp('web/public/nightbuoy.svg',join(root,'usr/share/icons/hicolor/scalable/apps/nightbuoy.svg'));
 await mkdir(join(root,'usr/share/doc/nightbuoy'),{recursive:true});await cp('LICENSE',join(root,'usr/share/doc/nightbuoy/copyright'));
 await text(join(root,'DEBIAN/control'),`Package: nightbuoy\nVersion: ${version}\nArchitecture: ${spec.deb}\nMaintainer: NightBuoy contributors\nDepends: libc6 (>= 2.39), libgcc-s1\nSection: net\nPriority: optional\nDescription: Portable encrypted forum client\n Local GUI and terminal interfaces for encrypted remote forum storage.\n`);
 run('dpkg-deb',['--root-owner-group','--build',root,artifact(name+'.deb')]);
 await rm(join(root,'DEBIAN'),{recursive:true});
 await text(join(root,'.PKGINFO'),`pkgname = nightbuoy\npkgbase = nightbuoy\npkgver = ${version}-1\npkgdesc = Portable encrypted forum client\nurl = https://github.com/MattJackson/nightbuoy\nbuilddate = ${Math.floor(Date.now()/1000)}\npackager = NightBuoy contributors\nsize = ${(await readFile(binary)).length}\narch = ${spec.arch}\nlicense = MIT\ndepend = glibc\ndepend = gcc-libs\n`);
 run('tar',['--zstd','--owner=0','--group=0','-cf',artifact(name+'.pkg.tar.zst'),'-C',root,'.PKGINFO','usr']);await rm(join(root,'.PKGINFO'));
 const rpmRoot=join(out,'rpm-build');for(const d of ['BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS'])await mkdir(join(rpmRoot,d),{recursive:true});
 // All paths below are controlled package roots, never user input or shell commands.
 const rpmSpec=join(rpmRoot,'SPECS/nightbuoy.spec');
 await text(rpmSpec,`Name: nightbuoy\nVersion: ${version}\nRelease: 1\nSummary: Portable encrypted forum client\nLicense: MIT\nURL: https://github.com/MattJackson/nightbuoy\nBuildArch: ${spec.rpm}\n%description\nLocal GUI and terminal interfaces for encrypted remote forum storage.\n%install\nmkdir -p "%{buildroot}"\ncp -a "${root}/usr" "%{buildroot}/"\n%files\n/usr/bin/nightbuoy\n/usr/share/applications/nightbuoy.desktop\n/usr/share/icons/hicolor/scalable/apps/nightbuoy.svg\n%license /usr/share/doc/nightbuoy/copyright\n`);
 run('rpmbuild',['-bb','--define',`_topdir ${rpmRoot}`,'--define','_build_id_links none','--define','__strip /bin/true','--define','debug_package %{nil}',rpmSpec]);
 for(const file of await readdir(join(rpmRoot,'RPMS',spec.rpm)))if(file.endsWith('.rpm'))await cp(join(rpmRoot,'RPMS',spec.rpm,file),artifact(file));
 await rm(root,{recursive:true});await rm(rpmRoot,{recursive:true});
}
const files=[...new Set(outputs)].sort();
const sums=[];for(const file of files)sums.push(createHash('sha256').update(await readFile(join(out,file))).digest('hex')+'  '+file);
await writeFile(join(out,'SHA256SUMS'),sums.join('\n')+'\n');
await writeFile(join(out,'build.json'),JSON.stringify({name:'NightBuoy',version,target,commit:process.env.GITHUB_SHA||null,signing:process.platform==='darwin'?'ad-hoc; not notarized':'unsigned',artifacts:files},null,2)+'\n');
console.log(`Packages prepared at ${out}`);
