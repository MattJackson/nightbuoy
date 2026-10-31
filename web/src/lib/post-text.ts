// A deliberately small text-to-DOM grammar. No HTML is generated or interpreted.
export type Inline={kind:'text'|'bold'|'italic'|'strike'|'code'|'spoiler'|'link';text:string;url?:string};
export type PostBlock={kind:'paragraph'|'heading'|'quote';parts:Inline[];level?:number}|{kind:'code';text:string;language:string}|{kind:'list';ordered:boolean;start?:number;items:Inline[][]};
type Budget={formats:number;units:number};
export function safePostLink(value:string):string|undefined {
 if(value.length>2048||/[\u0000-\u0020\u007f\\]/.test(value)||!/^https?:\/\//i.test(value))return;
 try{const u=new URL(value);if(u.username||u.password)return;if(u.protocol==='https:'||(u.protocol==='http:'&&/^[a-z2-7]{56}\.onion$/.test(u.hostname)))return u.href;}catch{}
}
const tokens=/`([^`\n]{1,1000})`|\*\*([^*\n]{1,2000})\*\*|~~([^~\n]{1,2000})~~|\|\|([^|\n]{1,2000})\|\||\*([^*\n]{1,2000})\*|(!?)\[([^\[\]\n]{1,240})\]\(((?:[^\s()]|\([^\s()]{1,240}\)){1,2048})\)|(https:\/\/[^\s<>\[\]`]{1,2048})(?=$|[\s<>\[\]`])/g;
function trimLinkEnd(value:string){let text=value.replace(/[.,;:!?'"»]+$/,'');let balance=0;for(const ch of text){if(ch==='(')balance++;else if(ch===')')balance--;}while(balance<0&&text.endsWith(')')){text=text.slice(0,-1);balance++;}return text;}
export function inlinePost(text:string,budget:Budget={formats:512,units:512}):Inline[]{
 const out:Inline[]=[];let at=0;
 for(const match of text.matchAll(tokens)){
  if(budget.formats<=0)break;const offset=match.index!;if(offset>at)out.push({kind:'text',text:text.slice(at,offset)});budget.formats--;
  let part:Inline;
  if(match[1]!==undefined)part={kind:'code',text:match[1]};
  else if(match[2]!==undefined)part={kind:'bold',text:match[2]};
  else if(match[3]!==undefined)part={kind:'strike',text:match[3]};
  else if(match[4]!==undefined)part={kind:'spoiler',text:match[4]};
  else if(match[5]!==undefined)part={kind:'italic',text:match[5]};
  else {
   const raw=match[8]??match[9],trimmed=match[9]?trimLinkEnd(raw):raw,url=safePostLink(trimmed);
   part=url?{kind:'link',text:match[7]!==undefined?(match[6]?'Image: ':'')+match[7]:trimmed,url}:{kind:'text',text:match[0]};
   if(match[9]&&url){out.push(part);const suffix=raw.slice(trimmed.length);if(suffix)out.push({kind:'text',text:suffix});at=offset+match[0].length;continue;}
  }
  out.push(part);at=offset+match[0].length;
 }
 if(at<text.length)out.push({kind:'text',text:text.slice(at)});return out;
}
const listLine=(line:string)=>/^ {0,3}([-*]|\d{1,4}\.)\s+(.+)$/.exec(line);
const startsBlock=(line:string)=>/^```|^#{1,3} |^>/.test(line)||!!listLine(line);
export function postBlocks(text:string):PostBlock[]{
 const lines=text.slice(0,100000).replace(/\r\n/g,'\n').split('\n'),blocks:PostBlock[]=[],budget={formats:512,units:512};let i=0;
 while(i<lines.length){
  if(budget.units<=0){blocks.push({kind:'paragraph',parts:[{kind:'text',text:lines.slice(i).join('\n')}]});break;}
  if(!lines[i].trim()){i++;continue;}
  const fence=/^```([a-zA-Z0-9_-]{0,30})\s*$/.exec(lines[i]);
  if(fence){i++;const code=[];while(i<lines.length&&!/^```\s*$/.test(lines[i]))code.push(lines[i++]);if(i<lines.length)i++;blocks.push({kind:'code',text:code.join('\n'),language:fence[1]});budget.units--;continue;}
  const heading=/^(#{1,3}) (.+)$/.exec(lines[i]);if(heading){blocks.push({kind:'heading',level:heading[1].length,parts:inlinePost(heading[2],budget)});i++;budget.units--;continue;}
  if(/^>/.test(lines[i])){const quote=[];while(i<lines.length&&/^>/.test(lines[i]))quote.push(lines[i++].replace(/^> ?/,''));blocks.push({kind:'quote',parts:inlinePost(quote.join('\n'),budget)});budget.units--;continue;}
  const first=listLine(lines[i]);if(first){const ordered=first[1].endsWith('.'),items:Inline[][]=[];while(i<lines.length&&budget.units>0){const next=listLine(lines[i]);if(!next||next[1].endsWith('.')!==ordered)break;items.push(inlinePost(next[2],budget));i++;budget.units--;}blocks.push({kind:'list',ordered,...(ordered?{start:parseInt(first[1],10)}:{}),items});continue;}
  const paragraph=[lines[i++]];while(i<lines.length&&lines[i].trim()&&!startsBlock(lines[i]))paragraph.push(lines[i++]);blocks.push({kind:'paragraph',parts:inlinePost(paragraph.join('\n'),budget)});budget.units--;
 }
 return blocks;
}
export type Format='bold'|'italic'|'strike'|'code'|'codeblock'|'spoiler'|'quote'|'list'|'heading'|'link';
export function formatSelection(body:string,start:number,end:number,format:Format){
 start=Math.max(0,Math.min(start,body.length));end=Math.max(start,Math.min(end,body.length));const selected=body.slice(start,end);let replacement='',from=0,to=0;
 if(format==='link'){const label=selected||'link',url='https://example.com';replacement=`[${label}](${url})`;from=label.length+3;to=from+url.length;}
 else if(['quote','list','heading','codeblock'].includes(format)){
  const gap=start>0&&body[start-1]!=='\n'?'\n':'';
  if(format==='codeblock'){const value=selected||'code';replacement=gap+'```\n'+value+'\n```\n';from=gap.length+4;to=from+value.length;}
  else{const prefix=format==='quote'?'> ':format==='list'?'- ':'### ',value=selected||(format==='heading'?'Heading':format==='list'?'Item':'quote');replacement=gap+value.split('\n').map(line=>prefix+line).join('\n');from=gap.length+prefix.length;to=replacement.length;if(end<body.length&&body[end]!=='\n')replacement+='\n';}
 }else{const marker={bold:'**',italic:'*',strike:'~~',code:'`',spoiler:'||'}[format as 'bold'|'italic'|'strike'|'code'|'spoiler'];const value=selected||(format==='code'?'code':'text');replacement=marker+value+marker;from=marker.length;to=from+value.length;}
 const next=body.slice(0,start)+replacement+body.slice(end);if(next.length>100000)throw Error('Keep the message below 100,000 characters.');return {body:next,start:start+from,end:start+to};
}
