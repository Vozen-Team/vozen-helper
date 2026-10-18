// Read-only inventory of Rust-owned reply templates. Never reads runtime data.
import fs from 'node:fs';
import crypto from 'node:crypto';
import assert from 'node:assert/strict';

function strings(source) {
  const result=[];const mask=source.split('');
  const blank=(start,end)=>{for(let p=start;p<end;p++)if(mask[p]!=='\n')mask[p]=' ';};
  for(let i=0;i<source.length;) {
    if(source.startsWith('//',i)){const start=i;i=source.indexOf('\n',i);if(i<0){blank(start,source.length);break;}blank(start,i);continue;}
    if(source.startsWith('/*',i)){const start=i;let depth=1;i+=2;while(depth&&i<source.length){if(source.startsWith('/*',i)){depth++;i+=2;}else if(source.startsWith('*/',i)){depth--;i+=2;}else i++;}blank(start,i);continue;}
    const raw=source.slice(i).match(/^r(#{0,16})"/);
    if(raw){const start=i;const end=source.indexOf('"'+raw[1],i+raw[0].length);if(end<0)throw Error('Unclosed raw string');result.push(source.slice(i+raw[0].length,end));i=end+raw[1].length+1;blank(start,i);continue;}
    if(source[i]==="'"&&source[i+2]==="'"){blank(i,i+3);i+=3;continue;}
    if(source[i]==="'"&&source[i+1]==='\\'&&source[i+3]==="'"){blank(i,i+4);i+=4;continue;}
    if(source[i]!=='"'){i++;continue;}
    const start=i;let value='';i++;
    while(i<source.length&&source[i]!=='"') {
      if(source[i]!=='\\'){value+=source[i++];continue;}
      const escaped=source[++i];i++;
      if(escaped==='u'&&source[i]==='{'){const end=source.indexOf('}',i);value+=String.fromCodePoint(parseInt(source.slice(i+1,end),16));i=end+1;}
      else if(escaped==='x'){value+=String.fromCharCode(parseInt(source.slice(i,i+2),16));i+=2;}
      else if(escaped==='\n'||escaped==='\r'){while(/\s/.test(source[i]||'')&&i<source.length)i++;}
      else value+=({n:'\n',r:'\r',t:'\t','0':'\0','\\':'\\','"':'"',"'":"'"})[escaped]??escaped;
    }
    result.push(value);i++;blank(start,i);
  }
  result.mask=mask.join('');
  return result;
}

function functions(source,matchName) {
  const mask=strings(source).mask;const found=[];
  for(const match of mask.matchAll(/\bfn\s+(\w+)\s*[(<]/g)) {
    if(!matchName(match[1]))continue;
    const open=mask.indexOf('{',match.index);let depth=1,end=open+1;
    while(depth&&end<mask.length){if(mask[end]==='{')depth++;if(mask[end]==='}')depth--;end++;}
    found.push(source.slice(match.index,end));
  }
  return found;
}

function template(value) {
  const names=new Map();let next=0;
  return value.replace(/\{\{|\}\}|\{([^{}]*)\}/g,(match,key)=>{
    if(match==='{{')return '{{';if(match==='}}')return '}}';
    // JSON literal objects and configured message variables are not Rust slots.
    if(!/^([A-Za-z_][\w]*|\d+)?(:[^{}]*)?$/.test(key))return match;
    const name=key.split(':')[0];
    if(name){if(!names.has(name))names.set(name,next++);return `{${names.get(name)}}`;}
    return `{${next++}}`;
  });
}

const main=fs.readFileSync('crates/helper-discord/src/lib.rs','utf8');
const slices=[main.slice(main.indexOf('async fn handle_command('),main.indexOf('fn edit_member_roles')),
  main.slice(main.indexOf('fn command_response_ephemeral('),main.indexOf('fn english_bot_text(')),
  ...functions(fs.readFileSync('crates/helper-core/src/lib.rs','utf8').split('#[cfg(test)]')[0],name=>name.startsWith('evaluate_')),
  ...functions(main,name=>name==='permission_passport_message'),
];
const sources=new Map();
const fragments=new Set(['; configure a role to restrict channels','; verification role updated',' without inviter names',' with inviter names',' (animated only)',' · internal note saved','display name matches `{pattern}`','account age {age_days}d < {minimum_age_days}d']);
for(const slice of slices)for(const text of strings(slice)) {
  // Include sentence/label templates, excluding keys, URLs, numeric formatting,
  // arbitrary data formats and lower-case internal error/log codes.
  if(!/\p{L}/u.test(text)||!/[\s]/.test(text)||text.length<8)continue;
  if(!/\p{L}{3}/u.test(text.replace(/\{[^{}]*\}/g,'')))continue;
  if(!/^[\s*#`]*(?:[A-ZÁÉÍÓÚÀÂÊÔÃÕÇ]|[\p{L}]+:)/u.test(text)&&!(/^[\s*#`<@]*\{[^{}]*\}/u.test(text))&&!fragments.has(text))continue;
  if(text.includes('://')&&!/^Dashboard:/.test(text))continue;
  if(text.includes('<svg')||text.startsWith('{"'))continue;
  const source=template(text);
  const id='r_'+crypto.createHash('sha256').update(source).digest('hex').slice(0,12);
  sources.set(id,source);
}
for(const source of ['Something went wrong while running that command.','Unable to complete this action.','Here is your Vozen Helper data export.']) {
  sources.set('r_'+crypto.createHash('sha256').update(source).digest('hex').slice(0,12),source);
}
const base=process.argv.includes('--extra')?JSON.parse(fs.readFileSync('crates/helper-discord/src/private-replies/source.json','utf8')):{};
const entries=[...sources].filter(([id])=>!(id in base)).sort(([a],[b])=>a.localeCompare(b));
if(process.argv.includes('--check')) {
  const directory='crates/helper-discord/src/private-replies/';
  const base=JSON.parse(fs.readFileSync(directory+'source.json','utf8'));
  const extra=JSON.parse(fs.readFileSync(directory+'extra-source.json','utf8'));
  const declared={...base,...extra};
  for(const [id,source] of entries)assert.equal(declared[id],source,`Uncatalogued current reply ${id}: ${source}`);
  const locales=['id','da','de','en-GB','en-US','es-ES','es-419','fr','hr','it','lt','hu','nl','no','pl','pt-BR','ro','fi','sv-SE','vi','tr','cs','el','bg','ru','uk','hi','th','zh-CN','ja','zh-TW','ko'];
  const placeholders=text=>[...text.matchAll(/\{\d+\}/g)].map(match=>match[0]).sort();
  for(const locale of locales) {
    for(const [suffix,source] of [['',base],['.extra',extra]]) {
      const target=JSON.parse(fs.readFileSync(directory+locale+suffix+'.json','utf8'));
      assert.deepEqual(Object.keys(target).sort(),Object.keys(source).sort(),locale+suffix);
      for(const [id,text] of Object.entries(source)) {
        assert.ok(typeof target[id]==='string'&&target[id].trim(),`${locale} ${id}: nonempty string`);
        assert.deepEqual(placeholders(target[id]),placeholders(text),`${locale} ${id}: slots`);
        const numbers=value=>(value.replace(/\{\d+\}/g,'').replace(/(?<=\d)[ \u00a0\u202f](?=\d{3}(?!\d))/g,'').match(/\d[\d,._]*/g)||[]).map(number=>number.replace(/[,._]/g,'')).sort();
        if(numbers(text).length)assert.deepEqual(numbers(target[id]),numbers(text),`${locale} ${id}: explicit factual numbers/limits`);
        for(const token of text.match(/<[@#][^>]+>|<t:[^>]+>|https?:\/\/[^\s)]+|(?<![\w:/])\/[a-z][a-z-]*/g)||[])assert.ok(target[id].includes(token),`${locale} ${id}: ${token}`);
      }
    }
    const words=JSON.parse(fs.readFileSync(directory+locale+'.words.json','utf8'));
    assert.deepEqual(Object.keys(words).sort(),['complete','pending','none','enabled','disabled','reacts','replies','disabled immediately','registered','checked_in','credits','exports','erasure','invalid_reaction','unsupported_action','First steps','Regular','Community pillar'].sort(),locale+' words');
    assert.ok(Object.values(words).every(word=>typeof word==='string'&&word.trim()));
  }
  console.log(`PASS ${locales.length} locales, ${Object.keys(declared).length} reply templates, status words, keys, slots and Discord tokens`);
}
else if(process.argv.includes('--stats'))console.log(JSON.stringify({count:entries.length,largest:entries.toSorted((a,b)=>b[1].length-a[1].length).slice(0,4)}));
else {const offset=Number(process.argv.find(arg=>/^\d+$/.test(arg))||0);console.log(JSON.stringify(Object.fromEntries(entries.slice(offset,offset+100)),null,2));}
