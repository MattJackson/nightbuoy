import {test} from 'node:test';import assert from 'node:assert/strict';
import {postBlocks,inlinePost,safePostLink,formatSelection} from '../web/src/lib/post-text.ts';
test('post text creates a bounded DOM model for formatting, code, quotes and lists',()=>{
 const blocks=postBlocks('# Heading\n\n**bold** and *italic* with ~~strike~~, `code` and ||secret||.\n\n> quoted\n> second line\n\n- one\n- two\n\n1. first\n2. second\n\n```rust\n<script>literal code</script>\n```');
 assert.equal(blocks[0].kind,'heading');assert.equal(blocks[1].kind,'paragraph');assert.deepEqual(blocks[1].kind==='paragraph'&&blocks[1].parts.filter(p=>p.kind!=='text').map(p=>p.kind),['bold','italic','strike','code','spoiler']);assert.equal(blocks[2].kind,'quote');assert.equal(blocks[3].kind,'list');assert.equal(blocks[4].kind,'list');assert.deepEqual(blocks[5],{kind:'code',language:'rust',text:'<script>literal code</script>'});
 const long=postBlocks(Array.from({length:2000},(_,i)=>'- row-'+i).join('\n'));assert.ok(long.length<515);const last=long.at(-1)!;assert.equal(last.kind,'paragraph');assert.ok(last.kind==='paragraph'&&last.parts[0].text.endsWith('row-1999'));
 const dense=inlinePost('**x** '.repeat(10000));assert.ok(dense.length<=1026);assert.ok(dense.at(-1)!.text.includes('**x**'));
});
test('links are explicit HTTPS or Tor navigation; images and HTML never become embedded media',()=>{
 for(const input of ['javascript:alert(1)','data:text/html,test','file:///etc/passwd','http://example.com','https://user:password@example.com','https://example.com/\nscript','https://example.com\\@elsewhere.com'])assert.equal(safePostLink(input),undefined);
 assert.equal(safePostLink('https://example.com/path'),'https://example.com/path');const onion='http://'+'a'.repeat(56)+'.onion/';assert.equal(safePostLink(onion),onion);
 const parts=inlinePost('[safe](https://example.com) [bad](javascript:alert) ![photo](https://images.example/image.png) <script>alert(1)</script>');
 assert.deepEqual(parts.filter(p=>p.kind==='link').map(p=>p.text),['safe','Image: photo']);assert.ok(parts.some(p=>p.text.includes('<script>')));assert.ok(parts.some(p=>p.text.includes('[bad](javascript:alert)')));
 assert.equal(inlinePost('[wiki](https://example.com/A_(B))').find(p=>p.kind==='link')?.url,'https://example.com/A_(B)');assert.equal(inlinePost('(https://example.com/A_(B)).').find(p=>p.kind==='link')?.url,'https://example.com/A_(B)');assert.equal(inlinePost('https://example.com/'+'a'.repeat(3000)).some(p=>p.kind==='link'),false);
 const literal=inlinePost('`https://example.com`');assert.deepEqual(literal,[{kind:'code',text:'https://example.com'}]);
});
test('composer tools preserve selected text, cursor targets and message bounds',()=>{
 assert.deepEqual(formatSelection('hello world',6,11,'bold'),{body:'hello **world**',start:8,end:13});
 const link=formatSelection('read this',5,9,'link');assert.equal(link.body.slice(link.start,link.end),'https://example.com');assert.equal(link.body,'read [this](https://example.com)');
 const quote=formatSelection('first\nsecond',0,12,'quote');assert.equal(quote.body,'> first\n> second');
 for(const kind of ['quote','list','heading'] as const){const edited=formatSelection('before selected after',7,15,kind);assert.ok(edited.body.endsWith('\n after'));assert.equal(edited.body.slice(edited.start,edited.end),'selected');}
 const ordered=postBlocks('7. seven\n8. eight')[0];assert.ok(ordered.kind==='list'&&ordered.start===7);
 assert.equal(postBlocks(formatSelection('',0,0,'codeblock').body)[0].kind,'code');
 assert.throws(()=>formatSelection('a'.repeat(100000),0,0,'bold'),/100,000/);
});
