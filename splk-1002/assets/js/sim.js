(function () {

  const D = window.SPLUNK_DATA;
  const events = D.events;
  const commands = D.commands;
  const categories = D.categories;

  let activeCmd = null;
  let feedTimer = null;
  let traceMode = false;

  
  const LOOKUP_TABLES = {
    usertogroup: [
      { username:'qays9',     group:'admin',    role:'power_user',  dept:'security' },
      { username:'hidden',    group:'ctf',      role:'analyst',     dept:'research' },
      { username:'osama',     group:'admin',    role:'power_user',  dept:'security' },
      { username:'wadee',     group:'dev',      role:'user',        dept:'engineering' },
      { username:'recruiter', group:'external', role:'viewer',      dept:'hr' },
      { username:'attacker',  group:'unknown',  role:'none',        dept:'external' },
      { username:'unknown',   group:'unknown',  role:'none',        dept:'external' }
    ],
    status_codes: [
      { status:'200', label:'OK',                 severity:'info' },
      { status:'301', label:'Moved Permanently',  severity:'warn' },
      { status:'403', label:'Forbidden',          severity:'high' },
      { status:'404', label:'Not Found',          severity:'warn' },
      { status:'500', label:'Internal Error',     severity:'critical' }
    ],
    hosts_meta: [
      { host:'qayssarayra.com',           owner:'qays9',  env:'prod', region:'us-east' },
      { host:'artifacts.qayssarayra.com', owner:'qays9',  env:'prod', region:'us-east' },
      { host:'qays.fun',                  owner:'qays9',  env:'dev',  region:'us-west' },
      { host:'ctfs.fun',                  owner:'hidden', env:'prod', region:'eu-west' },
      { host:'cryptera.ctfs.fun',         owner:'hidden', env:'prod', region:'eu-west' },
      { host:'osamaismail.com',           owner:'osama',  env:'prod', region:'ap-east' },
      { host:'wadeehaddad.com',           owner:'wadee',  env:'prod', region:'us-west' }
    ]
  };

  
  function highlightSPL(text) {
    const kwSet = new Set(['index','sourcetype','source','host','search','chart','timechart',
      'stats','eval','where','table','fields','sort','head','tail','dedup',
      'top','rare','rename','fillnull','filldown','rex','lookup','transaction','inputlookup',
      'outputlookup','join','append','appendcols','by','over','as','limit','span',
      'maxspan','maxpause','maxevents','startswith','endswith','count','sum',
      'avg','max','min','dc','values','list','mode','range','stdev','output','outputnew',
      'bin','bucket','eventstats','streamstats','addtotals','delta','accum',
      'regex','replace','makemv','mvexpand','not','and','or','in','like',
      'reverse','strcat','gauge','xyseries','untable','tstats','datamodel','makeresults','metadata']);

    const fnSet = new Set(['if','case','round','len','lower','upper','substr','replace',
      'tonumber','tostring','now','strftime','strptime','coalesce','isnull','isnotnull',
      'match','cidrmatch','mvcount','mvindex','mvjoin','mvsort','mvfilter',
      'like','first','last','perc95','perc99','md5','isint','isbool','isstr',
      'split','mvappend','abs','ceil','floor','sqrt','exp','log','pi',
      'urldecode','trim','ltrim','rtrim','nullif','typeof','time','relative_time',
      'exact','validate','null','random']);

    const indexKw = new Set(['index','sourcetype','source','host']);

    var esc = function(s) {
      return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    };

    var TOKEN = /(\s+)|(\|)|("(?:[^"\\]|\\.)*")|(#[^\n]*)|([a-zA-Z_][a-zA-Z0-9_]*)|([\S])/g;
    var out = '';
    var m;
    while ((m = TOKEN.exec(text)) !== null) {
      var ws = m[1], pipe = m[2], str = m[3], comment = m[4], word = m[5], punct = m[6];

      if (ws !== undefined) {
        out += esc(ws);
        continue;
      }
      if (pipe !== undefined) {
        out += ' <span class="spl-pipe">|</span> ';
        continue;
      }
      if (str !== undefined) {
        out += '<span class="spl-string">' + esc(str) + '</span>';
        continue;
      }
      if (comment !== undefined) {
        out += '<span class="spl-comment">' + esc(comment) + '</span>';
        continue;
      }
      if (word !== undefined) {
        var wordLow = word.toLowerCase();
        var rest = text.slice(m.index + word.length);
        var hasParen = /^\s*\(/.test(rest);
        var eqM = rest.match(/^=([^\s|#"()]+)/);

        if (hasParen) {
          if (fnSet.has(wordLow)) {
            out += '<span class="spl-func">' + esc(word) + '</span>';
          } else if (kwSet.has(wordLow)) {
            out += '<span class="spl-keyword">' + esc(word) + '</span>';
          } else {
            out += esc(word);
          }
        } else if (eqM) {
          TOKEN.lastIndex = m.index + word.length + 1 + eqM[1].length;
          var val = eqM[1];
          if (indexKw.has(wordLow)) {
            out += '<span class="spl-keyword">' + esc(word) + '</span>=<span class="spl-index">' + esc(val) + '</span>';
          } else if (kwSet.has(wordLow)) {
            out += '<span class="spl-keyword">' + esc(word) + '</span>=<span class="spl-value">' + esc(val) + '</span>';
          } else {
            out += '<span class="spl-field">' + esc(word) + '</span>=<span class="spl-value">' + esc(val) + '</span>';
          }
        } else {
          if (kwSet.has(wordLow)) {
            out += '<span class="spl-keyword">' + esc(word) + '</span>';
          } else {
            out += esc(word);
          }
        }
        continue;
      }
      if (punct !== undefined) {
        out += esc(punct);
      }
    }
    return out;
  }

  
  function runQuery(query, captureTrace) {
    let filtered = [...events];
    const rawPipes = query.split('|');
    const firstPipe = rawPipes[0].trim();
    const trace = [];

    if (firstPipe === '' || firstPipe === '*') {
      filtered = [...events];
    } else if (/^makeresults/i.test(firstPipe)) {
      filtered = execMakeresults(firstPipe);
    } else if (/^metadata/i.test(firstPipe)) {
      const r = execMetadata(firstPipe);
      filtered = r.rows.map(row => Object.fromEntries(r.columns.map((c,i)=>[c,row[i]])));
    } else if (/^inputlookup/i.test(firstPipe)) {
      const tbl = firstPipe.replace(/^inputlookup\s+/i,'').replace('.csv','').trim();
      filtered = LOOKUP_TABLES[tbl] ? [...LOOKUP_TABLES[tbl]] : [];
    } else {
      filtered = applyBaseSearch(filtered, firstPipe);
    }

    if (captureTrace) {
      trace.push({ label: 'Base Search', cmd: firstPipe || 'index=*', data: buildTableData(filtered) });
    }

    const pipes = rawPipes.slice(1).map(p => p.trim()).filter(Boolean);
    let outputType = 'events';
    let columns = [];
    let rows = [];

    for (const pipe of pipes) {
      const parts = pipe.trim().split(/\s+/);
      const cmd = parts[0].toLowerCase();

      if (cmd === 'stats') {
        const r = execStats(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'chart') {
        const r = execChart(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'timechart') {
        const r = execTimechart(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'top' || cmd === 'rare') {
        const r = execTop(filtered, pipe, cmd==='rare'); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'eval') {
        filtered = execEval(filtered, pipe);
      } else if (cmd === 'where') {
        filtered = execWhere(filtered, pipe);
      } else if (cmd === 'dedup') {
        filtered = execDedup(filtered, pipe);
      } else if (cmd === 'sort') {
        filtered = execSort(filtered, pipe);
      } else if (cmd === 'head') {
        const n = parseInt(parts[1]) || 10; filtered = filtered.slice(0, n);
      } else if (cmd === 'tail') {
        const n = parseInt(parts[1]) || 10; filtered = filtered.slice(-n);
      } else if (cmd === 'table') {
        const flist = pipe.replace(/^table\s+/i,'').split(',').map(f=>f.trim()).filter(Boolean);
        outputType='table'; columns=flist;
        rows = filtered.map(e => flist.map(f => e[f]!==undefined ? String(e[f]) : ''));
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'fields') {
        filtered = execFields(filtered, pipe);
      } else if (cmd === 'rename') {
        filtered = execRename(filtered, pipe);
      } else if (cmd === 'fillnull') {
        const vm = pipe.match(/value="?([^"\s]+)"?/i);
        const val = vm ? vm[1] : '0';
        filtered = filtered.map(e => {
          const o={...e};
          Object.keys(o).forEach(k => { if(o[k]===null||o[k]===undefined||o[k]==='') o[k]=val; });
          return o;
        });
      } else if (cmd === 'filldown') {
        filtered = execFilldown(filtered, pipe);
      } else if (cmd === 'rex') {
        filtered = execRex(filtered, pipe);
      } else if (cmd === 'regex') {
        filtered = execRegexFilter(filtered, pipe);
      } else if (cmd === 'search') {
        filtered = execSearchFilter(filtered, pipe.replace(/^search\s+/i,'').trim());
      } else if (cmd === 'transaction') {
        const r = execTransaction(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'inputlookup') {
        const tbl = parts[1] ? parts[1].replace('.csv','') : '';
        filtered = LOOKUP_TABLES[tbl] ? [...LOOKUP_TABLES[tbl]] : filtered;
      } else if (cmd === 'lookup') {
        filtered = execLookup(filtered, pipe);
      } else if (cmd === 'join') {
        filtered = execJoin(filtered, pipe);
      } else if (cmd === 'appendcols') {
        filtered = execAppendcols(filtered, pipe);
      } else if (cmd === 'bin' || cmd === 'bucket') {
        filtered = execBin(filtered, pipe);
      } else if (cmd === 'eventstats') {
        filtered = execEventstats(filtered, pipe);
      } else if (cmd === 'streamstats') {
        filtered = execStreamstats(filtered, pipe);
      } else if (cmd === 'addtotals') {
        filtered = execAddtotals(filtered, pipe);
      } else if (cmd === 'delta') {
        filtered = execDelta(filtered, pipe);
      } else if (cmd === 'accum') {
        filtered = execAccum(filtered, pipe);
      } else if (cmd === 'replace') {
        filtered = execReplace(filtered, pipe);
      } else if (cmd === 'makemv') {
        filtered = execMakemv(filtered, pipe);
      } else if (cmd === 'mvexpand') {
        filtered = execMvexpand(filtered, pipe);
      } else if (cmd === 'reverse') {
        filtered = [...filtered].reverse();
      } else if (cmd === 'append') {
        filtered = execAppend(filtered, pipe);
      } else if (cmd === 'strcat') {
        filtered = execStrcat(filtered, pipe);
      } else if (cmd === 'outputlookup') {
        filtered = execOutputlookup(filtered, pipe);
      } else if (cmd === 'gauge') {
        const r = execGauge(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'highlight') {
        filtered = filtered;
      } else if (cmd === 'xyseries') {
        const r = execXyseries(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'untable') {
        const r = execUntable(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'tstats') {
        const r = execTstats(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'datamodel') {
        const r = execDatamodel(filtered, pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      } else if (cmd === 'makeresults') {
        filtered = execMakeresults(pipe);
      } else if (cmd === 'metadata') {
        const r = execMetadata(pipe); outputType='table'; columns=r.columns; rows=r.rows;
        filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
      }

      if (captureTrace) {
        trace.push({ label: '| ' + cmd, cmd: pipe, data: buildTableData(filtered) });
      }
    }

    if (outputType === 'events' && filtered.length > 0) {
      const allKeys = [...new Set(filtered.flatMap(e=>Object.keys(e)))];
      const preferred = ['_time','host','user','method','uri','status','bytes','src_ip','action','sourcetype','session'];
      columns = [...preferred.filter(k=>allKeys.includes(k)), ...allKeys.filter(k=>!preferred.includes(k))];
      rows = filtered.map(e => columns.map(c => e[c]!==undefined ? String(e[c]) : ''));
      outputType = 'table';
      filtered = rows.map(row => Object.fromEntries(columns.map((c,i)=>[c,row[i]])));
    } else if (outputType === 'table' && rows.length > 0) {
      
    } else if (filtered.length === 0) {
      columns = []; rows = [];
    }

    
    if (outputType === 'table' && filtered.length > 0 && columns.length === 0) {
      const allKeys = [...new Set(filtered.flatMap(e=>Object.keys(e)))];
      columns = allKeys;
      rows = filtered.map(e => columns.map(c => e[c]!==undefined ? String(e[c]) : ''));
    }

    return { outputType, columns, rows, trace };
  }

  function buildTableData(evts) {
    if (!evts || evts.length === 0) return { columns: [], rows: [] };
    const allKeys = [...new Set(evts.flatMap(e=>Object.keys(e)))];
    const preferred = ['_time','host','user','method','uri','status','bytes','src_ip','action'];
    const columns = [...preferred.filter(k=>allKeys.includes(k)), ...allKeys.filter(k=>!preferred.includes(k))];
    const rows = evts.slice(0, 8).map(e => columns.map(c => e[c]!==undefined ? String(e[c]) : ''));
    return { columns, rows, total: evts.length };
  }

  
  function applyBaseSearch(evts, baseStr) {
    if (!baseStr || baseStr === '*' || baseStr === '') return [...evts];
    let result = [...evts];
    
    const fieldValRe = /(\w+)=(?:"([^"]*)"|(\S+))/g;
    let fm;
    while ((fm = fieldValRe.exec(baseStr)) !== null) {
      const field = fm[1];
      const val = (fm[2] !== undefined ? fm[2] : fm[3]).toLowerCase();
      if (field === 'index') continue; 
      result = result.filter(e => {
        const ev = String(e[field]||'').toLowerCase();
        if (val.includes('*')) {
          const re = new RegExp('^'+val.replace(/\*/g,'.*')+'$');
          return re.test(ev);
        }
        return ev === val;
      });
    }
    
    const notRe = /NOT\s+(\w+)=(?:"([^"]*)"|(\S+))/gi;
    let nm;
    while ((nm = notRe.exec(baseStr)) !== null) {
      const field = nm[1];
      const val = (nm[2] !== undefined ? nm[2] : nm[3]).toLowerCase();
      result = result.filter(e => String(e[field]||'').toLowerCase() !== val);
    }
    
    const cleaned = baseStr.replace(/NOT\s+\S+/gi,'').replace(/(\w+)=(?:"[^"]*"|\S+)/g,'').trim();
    if (cleaned) {
      const terms = cleaned.split(/\s+/).filter(t => t && !['AND','OR'].includes(t.toUpperCase()));
      terms.forEach(term => {
        const tl = term.toLowerCase();
        if (tl === '*') return;
        result = result.filter(e => JSON.stringify(e).toLowerCase().includes(tl));
      });
    }
    return result;
  }

  
  function execStats(evts, pipe) {
    const byM = pipe.match(/\bby\s+(.+)$/i);
    const byFields = byM ? byM[1].split(',').map(f=>f.trim()) : [];
    const fnPart = pipe.replace(/^stats\s+/i,'').replace(/\s+by\s+.+$/i,'').trim();
    const fnDefs = parseFuncDefs(fnPart);

    if (!byFields.length) {
      const row = fnDefs.map(fd => String(applyStatFn(evts, fd)));
      return { columns: fnDefs.map(fd=>fd.alias||fd.fn+'('+fd.field+')'), rows:[row] };
    }

    const groups = {};
    evts.forEach(e => {
      const key = byFields.map(f=>String(e[f]||'')).join('||');
      if (!groups[key]) groups[key] = { vals: byFields.map(f=>e[f]||''), evts:[] };
      groups[key].evts.push(e);
    });
    const columns = [...byFields, ...fnDefs.map(fd=>fd.alias||(fd.fn+'('+fd.field+')'))];
    const rows = Object.values(groups).map(g => [
      ...g.vals.map(String),
      ...fnDefs.map(fd => String(applyStatFn(g.evts, fd)))
    ]);
    return { columns, rows };
  }

  function parseFuncDefs(part) {
    const defs = [];
    
    const segments = [];
    let depth=0, cur='';
    for (const ch of part) {
      if (ch==='(') { depth++; cur+=ch; }
      else if (ch===')') { depth--; cur+=ch; }
      else if (ch===',' && depth===0) { segments.push(cur.trim()); cur=''; }
      else cur+=ch;
    }
    if (cur.trim()) segments.push(cur.trim());

    segments.forEach(seg => {
      const asM = seg.match(/^(.+?)\s+as\s+(\S+)$/i);
      const raw = asM ? asM[1].trim() : seg;
      const alias = asM ? asM[2] : null;
      const m = raw.match(/^(\w+)\(([^)]*)\)$/);
      if (m) defs.push({ fn: m[1].toLowerCase(), field: m[2].trim(), alias });
      else if (raw.toLowerCase() === 'count' || raw === '*') defs.push({ fn:'count', field:'*', alias });
      else defs.push({ fn:'count', field:'*', alias: raw });
    });
    return defs;
  }

  function applyStatFn(evts, fd) {
    const { fn, field } = fd;
    if (fn === 'count') return evts.length;
    const vals = evts.map(e=>e[field]).filter(v=>v!==undefined&&v!==null&&v!=='');
    const nums = vals.map(Number).filter(v=>!isNaN(v));
    if (fn === 'sum') return nums.reduce((a,b)=>a+b,0);
    if (fn === 'avg') return nums.length ? +(nums.reduce((a,b)=>a+b,0)/nums.length).toFixed(2) : 0;
    if (fn === 'max') return nums.length ? Math.max(...nums) : (vals.length ? [...vals].sort().pop() : '');
    if (fn === 'min') return nums.length ? Math.min(...nums) : (vals.length ? [...vals].sort()[0] : '');
    if (fn === 'dc') return new Set(vals.map(String)).size;
    if (fn === 'range') return nums.length ? Math.max(...nums)-Math.min(...nums) : 0;
    if (fn === 'values') return [...new Set(vals.map(String))].join(', ');
    if (fn === 'list') return vals.map(String).join(', ');
    if (fn === 'mode') {
      const freq={}; vals.forEach(v=>{ freq[v]=(freq[v]||0)+1; });
      return Object.entries(freq).sort((a,b)=>b[1]-a[1])[0]?.[0]||'';
    }
    if (fn === 'median') {
      if (!nums.length) return 0;
      const s=[...nums].sort((a,b)=>a-b);
      const mid=Math.floor(s.length/2);
      return s.length%2===0 ? +((s[mid-1]+s[mid])/2).toFixed(2) : s[mid];
    }
    if (fn === 'stdev') {
      if (!nums.length) return 0;
      const mean=nums.reduce((a,b)=>a+b,0)/nums.length;
      return +Math.sqrt(nums.reduce((a,b)=>a+(b-mean)**2,0)/nums.length).toFixed(4);
    }
    if (fn === 'var') {
      if (!nums.length) return 0;
      const mean=nums.reduce((a,b)=>a+b,0)/nums.length;
      return +(nums.reduce((a,b)=>a+(b-mean)**2,0)/nums.length).toFixed(4);
    }
    if (fn === 'sumsq') return nums.reduce((a,b)=>a+b*b,0);
    if (fn.startsWith('perc')) {
      const p = parseInt(fn.replace('perc',''))||50;
      const sorted=[...nums].sort((a,b)=>a-b);
      return sorted[Math.floor(p/100*sorted.length)]||0;
    }
    if (fn === 'earliest') return vals[0]||'';
    if (fn === 'latest') return vals[vals.length-1]||'';
    if (fn === 'first') return vals[0]||'';
    if (fn === 'last') return vals[vals.length-1]||'';
    return evts.length;
  }

  
  function execChart(evts, pipe) {
    const overM = pipe.match(/\bover\s+(\S+)/i);
    const byM = pipe.match(/\bby\s+([^|]+?)(?:\s+limit=|\s*$)/i);
    const fnRaw = pipe.replace(/^chart\s+/i,'').replace(/\bover\s+\S+/i,'').replace(/\bby\s+.+$/i,'').trim();
    const overField = overM ? overM[1] : null;
    let byFields = byM ? byM[1].trim().split(',').map(f=>f.trim()) : [];
    const fnDefs = parseFuncDefs(fnRaw||'count');
    const fd = fnDefs[0];
    const limitM = pipe.match(/\blimit=(\d+)/i);
    const limit = limitM ? parseInt(limitM[1]) : 100;

    if (!overField && byFields.length >= 2) {
      const xField = byFields[0], serField = byFields[1];
      const xVals = [...new Set(evts.map(e=>String(e[xField]||'')))].slice(0,limit);
      const serVals = [...new Set(evts.map(e=>String(e[serField]||'')))].slice(0,limit);
      const columns = [xField, ...serVals];
      const rows = xVals.map(xv => {
        const row = [xv];
        serVals.forEach(sv => {
          const subset = evts.filter(e=>String(e[xField]||'')==xv && String(e[serField]||'')==sv);
          row.push(String(applyStatFn(subset, fd)));
        });
        return row;
      });
      return { columns, rows };
    }

    const xF = overField || (byFields[0] || 'host');
    const serF = overField ? byFields[0] : null;
    const xVals = [...new Set(evts.map(e=>String(e[xF]||'')))].slice(0,limit);
    if (!serF) {
      const fnLabel = fd.alias || (fd.fn+'('+fd.field+')');
      const rows = xVals.map(xv => {
        const subset = evts.filter(e=>String(e[xF]||'')==xv);
        return [xv, String(applyStatFn(subset, fd))];
      });
      return { columns:[xF, fnLabel], rows };
    }
    const serVals = [...new Set(evts.map(e=>String(e[serF]||'')))].slice(0,limit);
    const columns = [xF, ...serVals];
    const rows = xVals.map(xv => {
      const row = [xv];
      serVals.forEach(sv => {
        const subset = evts.filter(e=>String(e[xF]||'')==xv && String(e[serF]||'')==sv);
        row.push(String(applyStatFn(subset, fd)));
      });
      return row;
    });
    return { columns, rows };
  }

  
  function execTimechart(evts, pipe) {
    const byM = pipe.match(/\bby\s+(\S+)/i);
    const byField = byM ? byM[1] : null;
    const spanM = pipe.match(/\bspan=(\S+)/i);
    const span = spanM ? spanM[1] : '1h';
    const fnPart = pipe.replace(/^timechart\s+/i,'').replace(/\bspan=\S+/i,'').replace(/\bby\s+\S+/i,'').trim();
    const fnDefs = parseFuncDefs(fnPart||'count');
    const fd = fnDefs[0];
    const hours = parseSpan(span);

    const buckets = {};
    evts.forEach(e => {
      const ts = parseTime(e._time);
      const bucket = Math.floor(ts/(hours*3600))*hours*3600;
      const tLabel = formatBucket(bucket, span);
      if (!buckets[tLabel]) buckets[tLabel] = [];
      buckets[tLabel].push(e);
    });

    const timeSlots = Object.keys(buckets).sort();
    if (!byField) {
      const fnLabel = fd.alias || (fd.fn+'('+fd.field+')');
      const rows = timeSlots.map(t => [t, String(applyStatFn(buckets[t], fd))]);
      return { columns:['_time', fnLabel], rows };
    }
    const serVals = [...new Set(evts.map(e=>String(e[byField]||'')))];
    const columns = ['_time', ...serVals];
    const rows = timeSlots.map(t => {
      const row = [t];
      serVals.forEach(sv => {
        const sub = buckets[t].filter(e=>String(e[byField]||'')==sv);
        row.push(String(applyStatFn(sub, fd)));
      });
      return row;
    });
    return { columns, rows };
  }

  function parseSpan(s) {
    if (!s) return 1;
    const m = s.match(/(\d+)(s|m|h|d)/);
    if (!m) return 1;
    const n = parseInt(m[1]);
    if (m[2]==='s') return n/3600;
    if (m[2]==='m') return n/60;
    if (m[2]==='h') return n;
    if (m[2]==='d') return n*24;
    return 1;
  }

  function parseTime(str) {
    if (!str) return Date.now()/1000;
    const d = new Date(str.replace(' ','T'));
    return isNaN(d.getTime()) ? Date.now()/1000 : d.getTime()/1000;
  }

  function formatBucket(epoch, span) {
    const d = new Date(epoch*1000);
    const pad = n=>String(n).padStart(2,'0');
    if (span.includes('d')) return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate());
    if (span.includes('m') && !span.includes('mo')) {
      return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+pad(d.getHours())+':'+pad(d.getMinutes());
    }
    return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+' '+pad(d.getHours())+':00';
  }

  
  function execTop(evts, pipe, rare) {
    const limitM = pipe.match(/\blimit=(\d+)/i);
    const limit = limitM ? parseInt(limitM[1]) : 10;
    const byM = pipe.match(/\bby\s+(.+)$/i);
    const body = pipe.replace(/^(?:top|rare)\s+/i,'').replace(/limit=\d+\s*/i,'').replace(/\bby\s+.+$/i,'').trim();
    const field = body.split(/\s+/)[0] || 'host';
    const byFields = byM ? byM[1].split(',').map(f=>f.trim()) : [];

    if (byFields.length) {
      const groups={};
      evts.forEach(e => {
        const bk=byFields.map(f=>String(e[f]||'')).join('||');
        const fv=String(e[field]||'');
        if(!groups[bk]) groups[bk]={bvals:byFields.map(f=>e[f]||''),freq:{}};
        groups[bk].freq[fv]=(groups[bk].freq[fv]||0)+1;
      });
      const columns=[field,...byFields,'count','percent'];
      const rows=[];
      Object.values(groups).forEach(g=>{
        const total=Object.values(g.freq).reduce((a,b)=>a+b,0);
        Object.entries(g.freq).sort((a,b)=>rare?a[1]-b[1]:b[1]-a[1]).slice(0,limit).forEach(([v,c])=>{
          rows.push([v,...g.bvals.map(String),String(c),(c/total*100).toFixed(2)+'%']);
        });
      });
      return { columns, rows };
    }

    const freq = {};
    evts.forEach(e => { const v=String(e[field]||''); freq[v]=(freq[v]||0)+1; });
    const total = evts.length;
    const sorted = Object.entries(freq).sort((a,b)=>rare?a[1]-b[1]:b[1]-a[1]).slice(0,limit);
    const columns = [field,'count','percent'];
    const rows = sorted.map(([v,c])=>[v,String(c),(c/total*100).toFixed(2)+'%']);
    return { columns, rows };
  }

  
  function execEval(evts, pipe) {
    
    const body = pipe.replace(/^eval\s+/i,'').trim();
    
    const assignments = [];
    let depth=0, cur='';
    for (const ch of body) {
      if (ch==='(') { depth++; cur+=ch; }
      else if (ch===')') { depth--; cur+=ch; }
      else if (ch===',' && depth===0) { assignments.push(cur.trim()); cur=''; }
      else cur+=ch;
    }
    if (cur.trim()) assignments.push(cur.trim());

    return evts.map(e => {
      let o = {...e};
      assignments.forEach(asgn => {
        const eqIdx = asgn.indexOf('=');
        if (eqIdx < 0) return;
        const fname = asgn.slice(0,eqIdx).trim();
        const expr = asgn.slice(eqIdx+1).trim();
        o[fname] = evalExpr(expr, o);
      });
      return o;
    });
  }

  function evalExpr(expr, e) {
    expr = expr.trim();

    
    if (/^if\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'if');
      if (inner !== null) {
        const args = splitArgs(inner);
        if (args.length >= 3) return evalBool(args[0],e) ? evalExpr(args[1],e) : evalExpr(args[2],e);
      }
    }

    
    if (/^case\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'case');
      if (inner !== null) {
        const args = splitArgs(inner);
        for (let i=0; i<args.length-1; i+=2) {
          if (evalBool(args[i].trim(),e)) return evalExpr(args[i+1],e);
        }
        return '';
      }
    }

    
    if (/^coalesce\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'coalesce');
      if (inner !== null) {
        const args = splitArgs(inner);
        for (const a of args) {
          const v = evalExpr(a.trim(), e);
          if (v !== null && v !== undefined && v !== '') return v;
        }
        return '';
      }
    }

    
    if (/^isnull\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'isnull');
      if (inner !== null) { const v=e[inner.trim()]; return (v===null||v===undefined||v==='') ? 'true' : 'false'; }
    }
    if (/^isnotnull\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'isnotnull');
      if (inner !== null) { const v=e[inner.trim()]; return (v!==null&&v!==undefined&&v!=='') ? 'true' : 'false'; }
    }
    if (/^isint\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'isint');
      if (inner !== null) { const v=evalExpr(inner.trim(),e); return !isNaN(parseInt(v)) && String(parseInt(v))===String(v).trim() ? 'true':'false'; }
    }
    if (/^isstr\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'isstr');
      if (inner !== null) { const v=evalExpr(inner.trim(),e); return isNaN(Number(v)) ? 'true':'false'; }
    }
    if (/^isbool\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'isbool');
      if (inner !== null) { const v=String(evalExpr(inner.trim(),e)).toLowerCase(); return (v==='true'||v==='false') ? 'true':'false'; }
    }
    if (/^typeof\s*\(/i.test(expr)) {
      const inner = extractInner(expr, 'typeof');
      if (inner !== null) {
        const v = evalExpr(inner.trim(), e);
        if (v===null||v===undefined) return 'Null';
        if (typeof v === 'boolean' || v==='true'||v==='false') return 'Boolean';
        if (!isNaN(Number(v))) return 'Number';
        return 'String';
      }
    }

    
    if (/^abs\s*\(/i.test(expr)) { const inner=extractInner(expr,'abs'); if(inner!==null) return Math.abs(Number(evalExpr(inner.trim(),e)))||0; }
    if (/^ceil\s*\(/i.test(expr)) { const inner=extractInner(expr,'ceil'); if(inner!==null) return Math.ceil(Number(evalExpr(inner.trim(),e))); }
    if (/^floor\s*\(/i.test(expr)) { const inner=extractInner(expr,'floor'); if(inner!==null) return Math.floor(Number(evalExpr(inner.trim(),e))); }
    if (/^sqrt\s*\(/i.test(expr)) { const inner=extractInner(expr,'sqrt'); if(inner!==null) return +Math.sqrt(Number(evalExpr(inner.trim(),e))).toFixed(6); }
    if (/^exp\s*\(/i.test(expr)) { const inner=extractInner(expr,'exp'); if(inner!==null) return +Math.exp(Number(evalExpr(inner.trim(),e))).toFixed(6); }
    if (/^pi\s*\(\s*\)/i.test(expr)) return Math.PI;
    if (/^null\s*\(\s*\)/i.test(expr)) return '';
    if (/^now\s*\(\s*\)/i.test(expr)) return Math.floor(Date.now()/1000);
    if (/^time\s*\(\s*\)/i.test(expr)) return Date.now()/1000;
    if (/^random\s*\(\s*\)/i.test(expr)) return Math.floor(Math.random()*2147483647);

    
    if (/^log\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'log');
      if (inner!==null) {
        const args=splitArgs(inner);
        const x=Number(evalExpr(args[0].trim(),e));
        const base=args.length>1?Number(evalExpr(args[1].trim(),e)):10;
        return +( Math.log(x)/Math.log(base) ).toFixed(6);
      }
    }

    
    if (/^round\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'round');
      if (inner!==null) {
        const args=splitArgs(inner);
        const v=Number(evalExpr(args[0].trim(),e));
        const d=args.length>1?parseInt(args[1]):0;
        return isNaN(v)?0:+v.toFixed(d);
      }
    }

    
    if (/^len\s*\(/i.test(expr)) { const inner=extractInner(expr,'len'); if(inner!==null) return String(evalExpr(inner.trim(),e)).length; }

    
    if (/^lower\s*\(/i.test(expr)) { const inner=extractInner(expr,'lower'); if(inner!==null) return String(evalExpr(inner.trim(),e)).toLowerCase(); }
    if (/^upper\s*\(/i.test(expr)) { const inner=extractInner(expr,'upper'); if(inner!==null) return String(evalExpr(inner.trim(),e)).toUpperCase(); }

    
    if (/^trim\s*\(/i.test(expr)) { const inner=extractInner(expr,'trim'); if(inner!==null) return String(evalExpr(inner.trim(),e)).trim(); }
    if (/^ltrim\s*\(/i.test(expr)) { const inner=extractInner(expr,'ltrim'); if(inner!==null){ const args=splitArgs(inner); const s=String(evalExpr(args[0].trim(),e)); const ch=args[1]?evalExpr(args[1].trim(),e):''; return ch?s.replace(new RegExp('^['+ch.replace(/[-[\]{}()*+?.,\\^$|#\s]/g,'\\$&')+']+'),''):s.trimStart(); } }
    if (/^rtrim\s*\(/i.test(expr)) { const inner=extractInner(expr,'rtrim'); if(inner!==null){ const args=splitArgs(inner); const s=String(evalExpr(args[0].trim(),e)); const ch=args[1]?evalExpr(args[1].trim(),e):''; return ch?s.replace(new RegExp('['+ch.replace(/[-[\]{}()*+?.,\\^$|#\s]/g,'\\$&')+']+$'),''):s.trimEnd(); } }

    
    if (/^substr\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'substr');
      if (inner!==null) {
        const args=splitArgs(inner);
        const s=String(evalExpr(args[0].trim(),e));
        const start=(parseInt(evalExpr(args[1].trim(),e))||1)-1;
        const len=args[2]?parseInt(evalExpr(args[2].trim(),e)):undefined;
        return len!==undefined?s.substr(start,len):s.substr(start);
      }
    }

    
    if (/^replace\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'replace');
      if (inner!==null) {
        const args=splitArgs(inner);
        const s=String(evalExpr(args[0].trim(),e));
        const pat=args[1]?String(evalExpr(args[1].trim(),e)).replace(/^"|"$/g,''):'';
        const rep=args[2]?String(evalExpr(args[2].trim(),e)).replace(/^"|"$/g,''):'';
        try { return s.replace(new RegExp(pat,'g'),rep); } catch{ return s; }
      }
    }

    
    if (/^match\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'match');
      if (inner!==null) {
        const args=splitArgs(inner);
        const s=String(evalExpr(args[0].trim(),e));
        const pat=args[1]?String(evalExpr(args[1].trim(),e)).replace(/^"|"$/g,''):'';
        try { return new RegExp(pat).test(s)?'true':'false'; } catch{ return 'false'; }
      }
    }

    
    if (/^like\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'like');
      if (inner!==null) {
        const args=splitArgs(inner);
        const s=String(evalExpr(args[0].trim(),e)).toLowerCase();
        const pat=(args[1]||'""').replace(/^"|"$/g,'').toLowerCase().replace(/%/g,'.*').replace(/_/g,'.');
        return new RegExp('^'+pat+'$').test(s)?'true':'false';
      }
    }

    
    if (/^cidrmatch\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'cidrmatch');
      if (inner!==null) {
        const args=splitArgs(inner);
        const cidr=(args[0]||'""').replace(/^"|"$/g,'');
        const ip=String(evalExpr(args[1].trim(),e));
        return cidrMatch(cidr,ip)?'true':'false';
      }
    }

    
    if (/^strftime\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'strftime');
      if (inner!==null) {
        const args=splitArgs(inner);
        const epoch=Number(evalExpr(args[0].trim(),e));
        const fmt=(args[1]||'"%Y-%m-%d"').replace(/^"|"$/g,'');
        return strftime(isNaN(epoch)?Date.now()/1000:epoch, fmt);
      }
    }

    
    if (/^tostring\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'tostring');
      if (inner!==null) {
        const args=splitArgs(inner);
        const v=evalExpr(args[0].trim(),e);
        if (args.length < 2) return String(v);
        const fmt=String(evalExpr(args[1].trim(),e)).replace(/^"|"$/g,'').toLowerCase();
        const n=Number(v);
        if (fmt==='commas') return isNaN(n)?'0':n.toLocaleString();
        if (fmt==='hex') return isNaN(n)?'0x0':'0x'+Math.floor(n).toString(16).toUpperCase();
        if (fmt==='duration') { const s=Math.floor(isNaN(n)?0:n); return Math.floor(s/3600)+':'+String(Math.floor((s%3600)/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0'); }
        return String(v);
      }
    }

    
    if (/^tonumber\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'tonumber');
      if (inner!==null) {
        const args=splitArgs(inner);
        const s=String(evalExpr(args[0].trim(),e));
        const base=args.length>1?parseInt(evalExpr(args[1].trim(),e)):10;
        const n=parseInt(s,base);
        return isNaN(n)?0:n;
      }
    }

    
    if (/^md5\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'md5');
      if (inner!==null) {
        const s=String(evalExpr(inner.trim(),e));
        return simpleMd5(s);
      }
    }

    
    if (/^mvcount\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'mvcount');
      if (inner!==null) { const v=e[inner.trim()]; return Array.isArray(v)?v.length:v?1:0; }
    }

    
    if (/^mvindex\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'mvindex');
      if (inner!==null) {
        const args=splitArgs(inner);
        const v=e[args[0].trim()];
        const idx=parseInt(evalExpr(args[1].trim(),e))||0;
        if (Array.isArray(v)) return v[idx]||'';
        return idx===0?v||'':'';
      }
    }

    
    if (/^mvjoin\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'mvjoin');
      if (inner!==null) {
        const args=splitArgs(inner);
        const v=e[args[0].trim()];
        const delim=(args[1]||'","').replace(/^"|"$/g,'');
        return Array.isArray(v)?v.join(delim):String(v||'');
      }
    }

    
    if (/^split\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'split');
      if (inner!==null) {
        const args=splitArgs(inner);
        const s=String(evalExpr(args[0].trim(),e));
        const delim=(args[1]||'","').replace(/^"|"$/g,'');
        return s.split(delim);
      }
    }

    
    if (/^nullif\s*\(/i.test(expr)) {
      const inner=extractInner(expr,'nullif');
      if (inner!==null) {
        const args=splitArgs(inner);
        const a=evalExpr(args[0].trim(),e), b=evalExpr(args[1].trim(),e);
        return String(a)===String(b)?'':a;
      }
    }

    
    if (expr.includes('.') && !expr.match(/^\d+\.\d+$/) && !expr.match(/^[\w_]+$/)) {
      const dotParts = splitByDot(expr);
      if (dotParts.length > 1) {
        return dotParts.map(p=>String(evalExpr(p.trim(),e))).join('');
      }
    }

    
    if (/[+\-*\/]/.test(expr) && !expr.startsWith('"')) {
      const m = splitArithmetic(expr);
      if (m) {
        const a=Number(evalExpr(m[0],e));
        const b=Number(evalExpr(m[2],e));
        if (!isNaN(a)&&!isNaN(b)) {
          if(m[1]==='+') return a+b;
          if(m[1]==='-') return a-b;
          if(m[1]==='*') return a*b;
          if(m[1]==='/'&&b!==0) return +(a/b).toFixed(4);
          if(m[1]==='%') return a%b;
        }
      }
    }

    
    const strM = expr.match(/^"([^"]*)"$/);
    if (strM) return strM[1];

    
    if (e[expr]!==undefined) return e[expr];

    
    const n=Number(expr);
    return isNaN(n)?expr:n;
  }

  function extractInner(expr, fnName) {
    const re = new RegExp('^'+fnName+'\\s*\\(','i');
    if (!re.test(expr)) return null;
    const start = expr.indexOf('(');
    if (start < 0) return null;
    let depth=1, i=start+1;
    while (i<expr.length && depth>0) {
      if (expr[i]==='(') depth++;
      else if (expr[i]===')') depth--;
      i++;
    }
    return depth===0 ? expr.slice(start+1, i-1) : null;
  }

  function splitArithmetic(expr) {
    
    let depth=0;
    let addSubPos=-1, mulDivPos=-1;
    for (let i=0; i<expr.length; i++) {
      if (expr[i]==='(') depth++;
      else if (expr[i]===')') depth--;
      else if (depth===0) {
        if ((expr[i]==='+'||expr[i]==='-') && i>0 && !(['+','-','*','/','('].includes(expr[i-1]))) addSubPos=i;
        else if ((expr[i]==='*'||expr[i]==='/'||expr[i]==='%') && i>0) mulDivPos=i;
      }
    }
    const pos = mulDivPos >= 0 ? mulDivPos : addSubPos;
    if (pos < 0) return null;
    return [expr.slice(0,pos).trim(), expr[pos], expr.slice(pos+1).trim()];
  }

  function splitByDot(expr) {
    const parts=[]; let depth=0, cur='';
    for (const ch of expr) {
      if (ch==='(') { depth++; cur+=ch; }
      else if (ch===')') { depth--; cur+=ch; }
      else if (ch==='.' && depth===0) { parts.push(cur); cur=''; }
      else cur+=ch;
    }
    if (cur) parts.push(cur);
    return parts;
  }

  function evalBool(cond, e) {
    cond = cond.trim();

    
    if (/^NOT\s+/i.test(cond)) return !evalBool(cond.replace(/^NOT\s+/i,'').trim(), e);

    
    const andIdx = findOperatorIdx(cond, 'AND');
    if (andIdx >= 0) return evalBool(cond.slice(0,andIdx).trim(),e) && evalBool(cond.slice(andIdx+3).trim(),e);

    
    const orIdx = findOperatorIdx(cond, 'OR');
    if (orIdx >= 0) return evalBool(cond.slice(0,orIdx).trim(),e) || evalBool(cond.slice(orIdx+2).trim(),e);

    
    const eqM = cond.match(/^(.+?)\s*(==|!=|>=|<=|>|<)\s*(.+)$/);
    if (eqM) {
      const a=evalExpr(eqM[1].trim(),e);
      const b=evalExpr(eqM[3].trim(),e);
      const na=Number(a),nb=Number(b);
      const useNum=!isNaN(na)&&!isNaN(nb);
      if(eqM[2]==='==') return useNum?na===nb:String(a)===String(b);
      if(eqM[2]==='!=') return useNum?na!==nb:String(a)!==String(b);
      if(eqM[2]==='>')  return useNum?na>nb:String(a)>String(b);
      if(eqM[2]==='<')  return useNum?na<nb:String(a)<String(b);
      if(eqM[2]==='>=') return useNum?na>=nb:String(a)>=String(b);
      if(eqM[2]==='<=') return useNum?na<=nb:String(a)<=String(b);
    }

    
    const singleEqM = cond.match(/^(\w+)\s*=\s*(?:"([^"]*)"|(\S+))$/);
    if (singleEqM) {
      const fval=String(e[singleEqM[1]]||'').toLowerCase();
      const target=(singleEqM[2]!==undefined?singleEqM[2]:singleEqM[3]).toLowerCase();
      if (target.includes('*')) return new RegExp('^'+target.replace(/\*/g,'.*')+'$').test(fval);
      return fval===target;
    }

    
    const isnullM = cond.match(/^isnotnull\s*\(([^)]+)\)$/i);
    if (isnullM) { const v=e[isnullM[1].trim()]; return v!==null&&v!==undefined&&v!==''; }
    const isnullM2 = cond.match(/^isnull\s*\(([^)]+)\)$/i);
    if (isnullM2) { const v=e[isnullM2[1].trim()]; return v===null||v===undefined||v===''; }

    
    const likeM = cond.match(/^like\s*\(([^,]+),\s*"([^"]*)"\)/i);
    if (likeM) {
      const val=String(evalExpr(likeM[1].trim(),e)).toLowerCase();
      const pat=likeM[2].toLowerCase().replace(/%/g,'.*').replace(/_/g,'.');
      return new RegExp('^'+pat+'$').test(val);
    }

    
    const matchM = cond.match(/^match\s*\(([^,]+),\s*"([^"]*)"\)/i);
    if (matchM) {
      const val=String(evalExpr(matchM[1].trim(),e));
      try { return new RegExp(matchM[2]).test(val); } catch { return false; }
    }

    
    const cidrM = cond.match(/^cidrmatch\s*\("([^"]+)",\s*(\S+)\)/i);
    if (cidrM) return cidrMatch(cidrM[1], String(e[cidrM[2]]||''));

    
    const inM = cond.match(/^in\s*\(([^,]+),(.+)\)$/i);
    if (inM) {
      const fieldVal=String(evalExpr(inM[1].trim(),e));
      const vals=splitArgs(inM[2]).map(v=>String(evalExpr(v.trim(),e)));
      return vals.includes(fieldVal);
    }

    if (cond==='1=1'||cond.toLowerCase()==='true') return true;
    if (cond.toLowerCase()==='false') return false;

    
    const v = evalExpr(cond, e);
    return v === 'true' || v === true || (typeof v === 'number' && v !== 0);
  }

  function findOperatorIdx(cond, op) {
    let depth=0;
    const opLen=op.length;
    for (let i=0; i<=cond.length-opLen; i++) {
      if (cond[i]==='(') depth++;
      else if (cond[i]===')') depth--;
      else if (depth===0 && cond.slice(i,i+opLen).toUpperCase()===op) {
        const before=cond[i-1]||' ', after=cond[i+opLen]||' ';
        if (/\s/.test(before) && /\s/.test(after)) return i;
      }
    }
    return -1;
  }

  function splitArgs(str) {
    const args=[]; let depth=0, cur='', inStr=false;
    for (const ch of str) {
      if (ch==='"' && !inStr) { inStr=true; cur+=ch; }
      else if (ch==='"' && inStr) { inStr=false; cur+=ch; }
      else if (!inStr && ch==='(') { depth++; cur+=ch; }
      else if (!inStr && ch===')') { depth--; cur+=ch; }
      else if (!inStr && ch===',' && depth===0) { args.push(cur.trim()); cur=''; }
      else cur+=ch;
    }
    if (cur.trim()) args.push(cur.trim());
    return args;
  }

  function execWhere(evts, pipe) {
    const expr = pipe.replace(/^where\s+/i,'').trim();
    return evts.filter(e => evalBool(expr, e));
  }

  function execDedup(evts, pipe) {
    const body = pipe.replace(/^dedup\s+/i,'').trim();
    const sortM = pipe.match(/\bsortby\s+(-?)(\S+)/i);
    const nM = body.match(/^(\d+)\s+/);
    const maxN = nM ? parseInt(nM[1]) : 1;
    let evtList = [...evts];
    if (sortM) {
      const desc = sortM[1]==='-';
      const f = sortM[2];
      evtList.sort((a,b) => {
        const na=Number(a[f]),nb=Number(b[f]);
        const useNum=!isNaN(na)&&!isNaN(nb);
        const cmp=useNum?(na-nb):(String(a[f]||'')>String(b[f]||'')?1:-1);
        return desc?-cmp:cmp;
      });
    }
    const rawFields = body.replace(/^\d+\s+/,'').replace(/\bsortby\s+\S+/i,'').trim();
    const fields = rawFields.split(/\s+/).filter(p=>!p.startsWith('sortby'));
    const seen = {};
    return evtList.filter(e => {
      const k = fields.map(f=>String(e[f]||'')).join('||');
      seen[k]=(seen[k]||0)+1;
      return seen[k] <= maxN;
    });
  }

  function execSort(evts, pipe) {
    const body = pipe.replace(/^sort\s+/i,'').replace(/limit=\d+/i,'').trim();
    const nM = body.match(/^(\d+)\s+/);
    const limit = nM ? parseInt(nM[1]) : null;
    const specStr = nM ? body.replace(/^\d+\s+/,'') : body;
    const specs = specStr.split(',').map(s=>s.trim()).filter(Boolean);
    const result = [...evts].sort((a,b) => {
      for (const spec of specs) {
        const desc = spec.startsWith('-');
        const f = spec.replace(/^[\+\-]/,'').trim();
        const na=Number(a[f]),nb=Number(b[f]);
        const useNum=!isNaN(na)&&!isNaN(nb);
        const cmp=useNum?(na-nb):(String(a[f]||'')>String(b[f]||'')?1:String(a[f]||'')<String(b[f]||'')?-1:0);
        if (cmp!==0) return desc?-cmp:cmp;
      }
      return 0;
    });
    return limit ? result.slice(0, limit) : result;
  }

  function execFields(evts, pipe) {
    const minus = /fields\s+-\s/i.test(pipe) || /fields\s+-[^\s]/i.test(pipe);
    const flist = pipe.replace(/^fields\s+[\+\-]?\s*/i,'').split(',').map(f=>f.trim()).filter(Boolean);
    if (!minus) {
      return evts.map(e => { const o={}; flist.forEach(f=>{ if(e[f]!==undefined) o[f]=e[f]; }); return o; });
    } else {
      return evts.map(e => { const o={...e}; flist.forEach(f=>delete o[f]); return o; });
    }
  }

  function execRename(evts, pipe) {
    const body = pipe.replace(/^rename\s+/i,'').trim();
    const pairs = body.split(',').map(s=>s.trim());
    return evts.map(e => {
      const o={...e};
      pairs.forEach(p => {
        const m = p.match(/^(\S+)\s+as\s+(\S+)$/i);
        if (m) { if(o[m[1]]!==undefined){ o[m[2]]=o[m[1]]; delete o[m[1]]; } }
      });
      return o;
    });
  }

  function execFilldown(evts, pipe) {
    const fields = pipe.replace(/^filldown\s+/i,'').split(',').map(f=>f.trim()).filter(Boolean);
    const lastVals = {};
    return evts.map(e => {
      const o={...e};
      (fields.length ? fields : Object.keys(o)).forEach(f => {
        if (o[f]===null||o[f]===undefined||o[f]==='') {
          if (lastVals[f]!==undefined) o[f]=lastVals[f];
        } else {
          lastVals[f]=o[f];
        }
      });
      return o;
    });
  }

  function execRex(evts, pipe) {
    const fieldM = pipe.match(/\bfield=(\S+)/i);
    const field = fieldM ? fieldM[1] : '_raw';
    const modeM = pipe.match(/\bmode=(\w+)/i);
    const mode = modeM ? modeM[1].toLowerCase() : 'extract';
    const patM = pipe.match(/"([^"]+)"/);
    if (!patM) return evts;
    const pat = patM[1];
    const namedGroups = [...pat.matchAll(/\(\?P?<([^>]+)>/g)].map(m=>m[1]);
    if (!namedGroups.length && mode !== 'sed') return evts;
    if (mode === 'sed') {
      
      const sedM = pat.match(/^s\/(.+?)\/([^\/]*)\/([gi]*)$/);
      if (!sedM) return evts;
      const re = new RegExp(sedM[1], sedM[3]||'');
      return evts.map(e => { const o={...e}; o[field]=String(o[field]||'').replace(re,sedM[2]); return o; });
    }
    const re = new RegExp(pat.replace(/\(\?P</g,'(?<'));
    return evts.map(e => {
      const src = String(e[field]||JSON.stringify(e));
      const m = src.match(re);
      if (!m||!m.groups) return e;
      const o={...e};
      namedGroups.forEach(g => { if(m.groups[g]!==undefined) o[g]=m.groups[g]; });
      return o;
    });
  }

  function execRegexFilter(evts, pipe) {
    const notMode = /regex\s+NOT\s/i.test(pipe);
    const body = pipe.replace(/^regex\s+(NOT\s+)?/i,'').trim();
    const fieldM = body.match(/^(\w+)\s*=\s*"([^"]+)"/);
    if (fieldM) {
      try {
        const re = new RegExp(fieldM[2]);
        return evts.filter(e => notMode ? !re.test(String(e[fieldM[1]]||'')) : re.test(String(e[fieldM[1]]||'')));
      } catch { return evts; }
    }
    const patM = body.match(/"([^"]+)"/);
    if (patM) {
      try {
        const re = new RegExp(patM[1]);
        return evts.filter(e => notMode ? !re.test(JSON.stringify(e)) : re.test(JSON.stringify(e)));
      } catch { return evts; }
    }
    return evts;
  }

  function execSearchFilter(evts, term) {
    if (!term || term === '*') return evts;
    
    const tokens = term.split(/\s+/);
    let result = [...evts];
    tokens.forEach(tok => {
      if (!tok || tok.toUpperCase() === 'AND') return;
      const notFlag = tok.startsWith('NOT ');
      const t = notFlag ? tok.slice(4) : tok;
      const fvM = t.match(/^(\w+)=(?:"([^"]*)"|(\S+))$/);
      if (fvM) {
        const field=fvM[1], val=(fvM[2]!==undefined?fvM[2]:fvM[3]).toLowerCase();
        if (val.includes('*')) {
          const re = new RegExp('^'+val.replace(/\*/g,'.*')+'$');
          result = result.filter(e => notFlag ? !re.test(String(e[field]||'').toLowerCase()) : re.test(String(e[field]||'').toLowerCase()));
        } else {
          result = result.filter(e => notFlag ? String(e[field]||'').toLowerCase()!==val : String(e[field]||'').toLowerCase()===val);
        }
      } else {
        const tl = t.toLowerCase();
        result = result.filter(e => {
          const found = JSON.stringify(e).toLowerCase().includes(tl);
          return notFlag ? !found : found;
        });
      }
    });
    return result;
  }

  function execTransaction(evts, pipe) {
    const body = pipe.replace(/^transaction\s+/i,'').trim();
    const maxspanM = body.match(/\bmaxspan=(\S+)/i);
    const maxpauseM = body.match(/\bmaxpause=(\S+)/i);
    const maxeventsM = body.match(/\bmaxevents=(\d+)/i);
    const startM = body.match(/\bstartswith="?([^"\s]+)"?/i);
    const endM = body.match(/\bendswith="?([^"\s]+)"?/i);
    const maxSpanSec = maxspanM ? parseSpan(maxspanM[1])*3600 : Infinity;
    const maxEvents = maxeventsM ? parseInt(maxeventsM[1]) : Infinity;
    const fields = body.replace(/\b(maxspan|maxpause|maxevents|startswith|endswith)=\S+/gi,'').trim().split(/\s+/).filter(Boolean);

    const groups = {};
    evts.forEach(e => {
      const k = fields.map(f=>String(e[f]||'')).join('||') || '_all';
      if (!groups[k]) groups[k]={key:k,fvals:fields.map(f=>e[f]||''),evts:[]};
      groups[k].evts.push(e);
    });
    const columns = [...(fields.length?fields:['group']),'eventcount','duration','_raw_sample'];
    const rows = Object.values(groups).map(g => {
      const ts = g.evts.map(e=>parseTime(e._time)).sort((a,b)=>a-b);
      const dur = ts.length>1 ? (Math.max(...ts)-Math.min(...ts)) : 0;
      const limited = maxEvents < Infinity ? g.evts.slice(0,maxEvents) : g.evts;
      const sample = limited.map(e=>e.uri||e.action||'event').join(' → ');
      const fpart = fields.length ? g.fvals.map(String) : ['group_'+g.key.slice(0,6)];
      return [...fpart, String(limited.length), dur.toFixed(1)+'s', sample];
    });
    return { columns, rows };
  }

  
  function execLookup(evts, pipe) {
    const body = pipe.replace(/^lookup\s+/i,'').trim();
    
    const parts = body.split(/\s+/);
    const tblName = parts[0].replace('.csv','');
    const tbl = LOOKUP_TABLES[tblName];
    if (!tbl) return evts;

    const outputM = body.match(/\bOUTPUT(?:NEW)?\s+(.+)$/i);
    const outputFields = outputM ? outputM[1].split(',').map(f=>f.trim()) : null;

    
    const tblKeys = Object.keys(tbl[0]||{});
    const matchBody = body.replace(/^[^\s]+\s+/,'').replace(/\bOUTPUT(?:NEW)?\s+.+$/i,'').trim();
    const matchParts = matchBody.split(/\s+/).filter(Boolean);

    return evts.map(e => {
      const o={...e};
      
      let matched = null;
      for (const mp of matchParts) {
        const asM = mp.match(/^(.+)\s+as\s+(.+)$/i);
        const evtField = asM ? asM[1] : mp;
        const tblField = asM ? asM[2] : mp;
        if (tblKeys.includes(tblField) && e[evtField]!==undefined) {
          const evtVal = String(e[evtField]).toLowerCase();
          matched = tbl.find(row => String(row[tblField]).toLowerCase()===evtVal);
          if (matched) break;
        }
      }
      if (!matched) {
        
        for (const tk of tblKeys) {
          if (e[tk]!==undefined) {
            matched = tbl.find(row => String(row[tk]).toLowerCase()===String(e[tk]).toLowerCase());
            if (matched) break;
          }
        }
      }
      if (matched) {
        if (outputFields) {
          outputFields.forEach(f => { const asM=f.match(/^(\S+)\s+as\s+(\S+)$/i); const src=asM?asM[1]:f, dst=asM?asM[2]:f; if(matched[src]!==undefined) o[dst]=matched[src]; });
        } else {
          Object.entries(matched).forEach(([k,v])=>{ if(!e[k]||e[k]===undefined) o[k]=v; });
        }
      }
      return o;
    });
  }

  
  function execJoin(evts, pipe) {
    
    const typeM = pipe.match(/\btype=(\w+)/i);
    const type = typeM ? typeM[1].toLowerCase() : 'inner';
    const body = pipe.replace(/^join\s+/i,'').replace(/\btype=\w+\s*/i,'').trim();
    const fieldM = body.match(/^(\w+)/);
    const joinField = fieldM ? fieldM[1] : null;
    if (!joinField) return evts;

    
    let subEvts = null;
    for (const [tname, tbl] of Object.entries(LOOKUP_TABLES)) {
      if (tbl[0] && tbl[0][joinField]!==undefined) { subEvts = tbl; break; }
    }
    if (!subEvts) return evts;

    if (type === 'inner') {
      return evts.map(e => {
        const match = subEvts.find(r=>String(r[joinField]).toLowerCase()===String(e[joinField]||'').toLowerCase());
        if (!match) return null;
        return {...e, ...Object.fromEntries(Object.entries(match).filter(([k])=>k!==joinField))};
      }).filter(Boolean);
    }
    if (type === 'left') {
      return evts.map(e => {
        const match = subEvts.find(r=>String(r[joinField]).toLowerCase()===String(e[joinField]||'').toLowerCase());
        return match ? {...e, ...Object.fromEntries(Object.entries(match).filter(([k])=>k!==joinField))} : e;
      });
    }
    return evts;
  }

  
  function execAppendcols(evts, pipe) {
    
    
    const subEvts = LOOKUP_TABLES.usertogroup || [];
    return evts.map((e,i) => {
      const sub = subEvts[i % subEvts.length] || {};
      return { ...e, _appended_group: sub.group||'', _appended_role: sub.role||'' };
    });
  }

  
  function execBin(evts, pipe) {
    const spanM = pipe.match(/\bspan=(\S+)/i);
    const binsM = pipe.match(/\bbins=(\d+)/i);
    const body = pipe.replace(/^(?:bin|bucket)\s+/i,'').replace(/\bspan=\S+/i,'').replace(/\bbins=\d+/i,'').trim();
    const asM = body.match(/(\w+)\s+as\s+(\w+)/i);
    const field = asM ? asM[1] : body.split(/\s+/)[0];
    const alias = asM ? asM[2] : field;
    const span = spanM ? spanM[1] : null;

    return evts.map(e => {
      const o={...e};
      const v = e[field];
      if (field === '_time' || field === 'time') {
        const ts = parseTime(String(v||''));
        const hours = span ? parseSpan(span) : 1;
        const bucket = Math.floor(ts/(hours*3600))*hours*3600;
        o[alias] = formatBucket(bucket, span||'1h');
      } else {
        const n = Number(v);
        if (!isNaN(n)) {
          if (span) {
            const spanN = parseFloat(span);
            o[alias] = String(Math.floor(n/spanN)*spanN);
          } else if (binsM) {
            const bins = parseInt(binsM[1]);
            const allVals = evts.map(ee=>Number(ee[field])).filter(x=>!isNaN(x));
            const mn=Math.min(...allVals), mx=Math.max(...allVals);
            const binSize=(mx-mn)/bins;
            o[alias] = String(+(mn+Math.floor((n-mn)/binSize)*binSize).toFixed(2));
          } else {
            o[alias] = String(Math.floor(n/100)*100);
          }
        }
      }
      return o;
    });
  }

  
  function execEventstats(evts, pipe) {
    const byM = pipe.match(/\bby\s+(.+)$/i);
    const byFields = byM ? byM[1].split(',').map(f=>f.trim()) : [];
    const fnPart = pipe.replace(/^eventstats\s+/i,'').replace(/\s+by\s+.+$/i,'').trim();
    const fnDefs = parseFuncDefs(fnPart);

    if (!byFields.length) {
      const statVals = fnDefs.reduce((acc,fd) => {
        acc[fd.alias||(fd.fn+'('+fd.field+')')] = applyStatFn(evts, fd);
        return acc;
      }, {});
      return evts.map(e => ({...e, ...statVals}));
    }

    const groups = {};
    evts.forEach(e => {
      const key = byFields.map(f=>String(e[f]||'')).join('||');
      if (!groups[key]) groups[key] = [];
      groups[key].push(e);
    });

    return evts.map(e => {
      const key = byFields.map(f=>String(e[f]||'')).join('||');
      const grp = groups[key] || [e];
      const statVals = fnDefs.reduce((acc,fd) => {
        acc[fd.alias||(fd.fn+'('+fd.field+')')] = applyStatFn(grp, fd);
        return acc;
      }, {});
      return {...e, ...statVals};
    });
  }

  
  function execStreamstats(evts, pipe) {
    const windowM = pipe.match(/\bwindow=(\d+)/i);
    const resetM = pipe.match(/\breset_on_change=(true|false)/i);
    const byM = pipe.match(/\bby\s+(.+)$/i);
    const byFields = byM ? byM[1].split(',').map(f=>f.trim()) : [];
    const fnPart = pipe.replace(/^streamstats\s+/i,'').replace(/\bwindow=\d+\s*/i,'').replace(/\breset_on_change=\w+\s*/i,'').replace(/\s+by\s+.+$/i,'').trim();
    const fnDefs = parseFuncDefs(fnPart);
    const window = windowM ? parseInt(windowM[1]) : null;

    const buckets = {};
    return evts.map((e,i) => {
      const key = byFields.length ? byFields.map(f=>String(e[f]||'')).join('||') : '_all';
      if (!buckets[key]) buckets[key] = [];
      buckets[key].push(e);
      const window_evts = window ? buckets[key].slice(-window) : buckets[key];
      const statVals = fnDefs.reduce((acc,fd) => {
        acc[fd.alias||(fd.fn+'('+fd.field+')')] = applyStatFn(window_evts, fd);
        return acc;
      }, {});
      return {...e, ...statVals};
    });
  }

  
  function execAddtotals(evts, pipe) {
    const rowM = pipe.match(/\brow=(true|false)/i);
    const colM = pipe.match(/\bcol=(true|false)/i);
    const fieldnameM = pipe.match(/\bfieldname=(\S+)/i);
    const labelM = pipe.match(/\blabel=(\S+)/i);
    const labelFieldM = pipe.match(/\blabelfield=(\S+)/i);
    const addRow = !rowM || rowM[1].toLowerCase()!=='false';
    const addCol = colM && colM[1].toLowerCase()==='true';
    const totalField = fieldnameM ? fieldnameM[1] : 'Total';

    let result = evts.map(e => {
      if (!addRow) return e;
      const numFields = Object.entries(e).filter(([k,v])=>!isNaN(Number(v))&&k!=='status');
      const total = numFields.reduce((s,[,v])=>s+Number(v),0);
      return {...e, [totalField]: total};
    });

    if (addCol) {
      const label = labelM ? labelM[1] : 'Total';
      const labelField = labelFieldM ? labelFieldM[1] : Object.keys(evts[0]||{})[0];
      const totals = {};
      const numFields = Object.keys(evts[0]||{}).filter(k=>evts.every(e=>!isNaN(Number(e[k])))&&k!=='status');
      numFields.forEach(f => { totals[f]=String(evts.reduce((s,e)=>s+Number(e[f]||0),0)); });
      result.push({...totals, [labelField]: label});
    }
    return result;
  }

  
  function execDelta(evts, pipe) {
    const body = pipe.replace(/^delta\s+/i,'').trim();
    const asM = body.match(/^(\w+)\s+as\s+(\w+)$/i);
    const field = asM ? asM[1] : body.split(/\s+/)[0];
    const alias = asM ? asM[2] : field+'_delta';
    let prev = null;
    return evts.map(e => {
      const cur = Number(e[field]);
      const delta = prev !== null && !isNaN(cur) && !isNaN(prev) ? cur - prev : 0;
      prev = isNaN(cur) ? prev : cur;
      return {...e, [alias]: delta};
    });
  }

  
  function execAccum(evts, pipe) {
    const body = pipe.replace(/^accum\s+/i,'').trim();
    const asM = body.match(/^(\w+)\s+as\s+(\w+)$/i);
    const field = asM ? asM[1] : body.split(/\s+/)[0];
    const alias = asM ? asM[2] : field+'_accum';
    let running = 0;
    return evts.map(e => {
      const v = Number(e[field]);
      running += isNaN(v) ? 0 : v;
      return {...e, [alias]: running};
    });
  }

  
  function execReplace(evts, pipe) {
    
    const withM = pipe.match(/^replace\s+"?([^"]+)"?\s+WITH\s+"?([^"]+)"?\s+IN\s+(.+)$/i);
    if (!withM) return evts;
    const from = withM[1].trim();
    const to = withM[2].trim();
    const fields = withM[3].split(',').map(f=>f.trim());
    return evts.map(e => {
      const o={...e};
      fields.forEach(f => {
        if (o[f]!==undefined) {
          const s=String(o[f]);
          o[f] = from.includes('*') ? s.replace(new RegExp(from.replace(/\*/g,'.*'),'i'),to) : s.replace(new RegExp(from,'gi'),to);
        }
      });
      return o;
    });
  }

  
  function execMakemv(evts, pipe) {
    const delimM = pipe.match(/\bdelim="?([^"\s]+)"?/i);
    const delim = delimM ? delimM[1] : ' ';
    const body = pipe.replace(/^makemv\s+/i,'').replace(/\bdelim=\S+/i,'').trim();
    const field = body.trim();
    return evts.map(e => {
      const o={...e};
      if (o[field]) o[field]=String(o[field]).split(delim);
      return o;
    });
  }

  
  function execMvexpand(evts, pipe) {
    const field = pipe.replace(/^mvexpand\s+/i,'').trim().split(/\s+/)[0];
    const result = [];
    evts.forEach(e => {
      const v = e[field];
      if (Array.isArray(v)) {
        v.forEach(val => result.push({...e, [field]: val}));
      } else {
        result.push(e);
      }
    });
    return result;
  }

  
  function cidrMatch(cidr, ip) {
    try {
      const [net, bits] = cidr.split('/');
      const mask = bits ? ~((1<<(32-parseInt(bits)))-1) : -1;
      const ipToInt = s => s.split('.').reduce((a,b)=>(a<<8)+parseInt(b),0);
      return (ipToInt(net)&mask) === (ipToInt(ip)&mask);
    } catch { return false; }
  }

  
  function strftime(epoch, fmt) {
    const d = new Date(epoch*1000);
    const pad = n=>String(n).padStart(2,'0');
    const days=['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
    const months=['January','February','March','April','May','June','July','August','September','October','November','December'];
    return fmt
      .replace(/%Y/g, d.getFullYear())
      .replace(/%y/g, String(d.getFullYear()).slice(-2))
      .replace(/%m/g, pad(d.getMonth()+1))
      .replace(/%d/g, pad(d.getDate()))
      .replace(/%H/g, pad(d.getHours()))
      .replace(/%I/g, pad(d.getHours()%12||12))
      .replace(/%M/g, pad(d.getMinutes()))
      .replace(/%S/g, pad(d.getSeconds()))
      .replace(/%p/g, d.getHours()<12?'AM':'PM')
      .replace(/%A/g, days[d.getDay()])
      .replace(/%a/g, days[d.getDay()].slice(0,3))
      .replace(/%B/g, months[d.getMonth()])
      .replace(/%b/g, months[d.getMonth()].slice(0,3))
      .replace(/%j/g, String(Math.floor((d-new Date(d.getFullYear(),0,0))/86400000)).padStart(3,'0'))
      .replace(/%s/g, Math.floor(epoch));
  }

  
  function simpleMd5(s) {
    let h = 0;
    for (let i=0; i<s.length; i++) h = (Math.imul(31,h)+s.charCodeAt(i))|0;
    return (h>>>0).toString(16).padStart(8,'0').repeat(4).slice(0,32);
  }

  function execAppend(evts, pipe) {
    const subRows = [
      { _time:'2025-09-09 09:00:00', host:'appended.host', status:200, uri:'/appended/result', bytes:1234, user:'append_user', method:'GET', action:'success', src_ip:'10.0.0.1', sourcetype:'access_combined', session:'sess_ap' },
      { _time:'2025-09-09 09:01:00', host:'appended.host', status:404, uri:'/appended/missing', bytes:333, user:'-', method:'GET', action:'not_found', src_ip:'10.0.0.2', sourcetype:'access_combined', session:'sess_ap' }
    ];
    return [...evts, ...subRows];
  }

  function execStrcat(evts, pipe) {
    const body = pipe.replace(/^strcat\s+/i,'').trim();
    const asM = body.match(/\s+as\s+(\S+)$/i);
    const alias = asM ? asM[1] : 'strcat_result';
    const fieldStr = asM ? body.replace(/\s+as\s+\S+$/i,'').trim() : body;
    const parts = fieldStr.split(/\s+/);
    return evts.map(e => {
      const val = parts.map(p => {
        if (p.startsWith('"') && p.endsWith('"')) return p.slice(1,-1);
        return String(e[p]||'');
      }).join('');
      return {...e, [alias]: val};
    });
  }

  function execOutputlookup(evts, pipe) {
    const fname = pipe.replace(/^outputlookup\s+/i,'').trim().split(/\s+/)[0] || 'output.csv';
    return evts.map(e => ({...e, _outputlookup_target: fname}));
  }

  function execGauge(evts, pipe) {
    const body = pipe.replace(/^gauge\s+/i,'').trim();
    const parts = body.split(/\s+/);
    const field = parts[0] || 'count';
    const thresholds = parts.slice(1).map(Number).filter(n=>!isNaN(n));
    const [t0=0, t1=50, t2=100, t3=200] = thresholds;
    const columns = [field, 'range', 'color'];
    const rows = evts.map(e => {
      const v = Number(e[field]) || 0;
      let range, color;
      if (v < t1)      { range='green';  color='#22c55e'; }
      else if (v < t2) { range='yellow'; color='#eab308'; }
      else if (v < t3) { range='orange'; color='#f97316'; }
      else             { range='red';    color='#ef4444'; }
      return [String(v), range, color];
    });
    return { columns, rows };
  }

  function execXyseries(evts, pipe) {
    const body = pipe.replace(/^xyseries\s+/i,'').trim();
    const parts = body.split(/\s+/);
    const xField = parts[0], yField = parts[1], valField = parts[2];
    if (!xField || !yField || !valField) return { columns: Object.keys(evts[0]||{}), rows: evts.map(e=>Object.values(e).map(String)) };
    const xVals = [...new Set(evts.map(e=>String(e[xField]||'')))];
    const yVals = [...new Set(evts.map(e=>String(e[yField]||'')))];
    const columns = [xField, ...yVals];
    const lookup = {};
    evts.forEach(e => { lookup[String(e[xField]||'')+'||'+String(e[yField]||'')] = String(e[valField]||'0'); });
    const rows = xVals.map(xv => [xv, ...yVals.map(yv => lookup[xv+'||'+yv]||'0')]);
    return { columns, rows };
  }

  function execUntable(evts, pipe) {
    const body = pipe.replace(/^untable\s+/i,'').trim();
    const parts = body.split(/\s+/);
    const rowField = parts[0] || '_time';
    const colField = parts[1] || 'field';
    const valField = parts[2] || 'value';
    const result = [];
    evts.forEach(e => {
      Object.entries(e).forEach(([k,v]) => {
        if (k === rowField) return;
        result.push({ [rowField]: e[rowField]||'', [colField]: k, [valField]: String(v) });
      });
    });
    const columns = [rowField, colField, valField];
    const rows = result.map(r => columns.map(c=>String(r[c]||'')));
    return { columns, rows };
  }

  function execTstats(evts, pipe) {
    const byM = pipe.match(/\bby\s+(.+)$/i);
    const byFields = byM ? byM[1].split(',').map(f=>f.trim()) : [];
    const fnPart = pipe.replace(/^tstats\s+/i,'').replace(/\bwhere\s+.+?(?=\||\bby\b|$)/i,'').replace(/\s+by\s+.+$/i,'').trim();
    const fnDefs = parseFuncDefs(fnPart||'count');
    const note = '[tstats: fast stats on accelerated data model tsidx summaries]';
    if (!byFields.length) {
      const row = fnDefs.map(fd => String(applyStatFn(evts, fd)));
      const columns = fnDefs.map(fd=>fd.alias||fd.fn+'('+fd.field+')');
      return { columns: [...columns, '_note'], rows: [[...row, note]] };
    }
    const groups = {};
    evts.forEach(e => {
      const key = byFields.map(f=>{ const fShort=f.includes('.')?f.split('.').pop():f; return String(e[fShort]||''); }).join('||');
      if (!groups[key]) groups[key]={ vals: byFields.map(f=>{ const fShort=f.includes('.')?f.split('.').pop():f; return e[fShort]||''; }), evts:[] };
      groups[key].evts.push(e);
    });
    const columns = [...byFields, ...fnDefs.map(fd=>fd.alias||(fd.fn+'('+fd.field+')'))];
    const rows = Object.values(groups).map(g => [...g.vals.map(String), ...fnDefs.map(fd=>String(applyStatFn(g.evts,fd)))]);
    return { columns, rows };
  }

  function execDatamodel(evts, pipe) {
    const parts = pipe.replace(/^datamodel\s+/i,'').trim().split(/\s+/);
    const modelName = parts[0] || 'Authentication';
    const datasetName = parts[1] || 'Authentication';
    const columns = [modelName+'.user', modelName+'.src', modelName+'.action', modelName+'.app', modelName+'._time'];
    const rows = evts.slice(0,8).map(e => [
      String(e.user||'-'), String(e.src_ip||'-'), String(e.action||'-'), String(e.sourcetype||'-'), String(e._time||'-')
    ]);
    return { columns, rows };
  }

  function execMakeresults(pipe) {
    const countM = pipe.match(/\bcount=(\d+)/i);
    const count = countM ? parseInt(countM[1]) : 1;
    const annotateM = pipe.match(/\bannotate=(true|false)/i);
    return Array.from({length: count}, (_,i) => ({ _time: String(Math.floor(Date.now()/1000)-i), _raw:'', count: String(i+1) }));
  }

  function execMetadata(pipe) {
    const typeM = pipe.match(/\btype=(\w+)/i);
    const indexM = pipe.match(/\bindex=(\S+)/i);
    const type = typeM ? typeM[1] : 'sourcetypes';
    const index = indexM ? indexM[1] : 'web_logs';
    const columns = [type.replace(/s$/,''), 'totalCount', 'firstTime', 'lastTime', 'recentTime'];
    const rows = [
      ['access_combined', '27', '2025-09-09 09:00:09', '2025-09-09 09:39:39', '2025-09-09 09:39:39'],
      ['web_logs',        '27', '2025-09-09 09:00:09', '2025-09-09 09:39:39', '2025-09-09 09:39:33']
    ];
    return { columns, rows };
  }

  function renderTable(result, compact) {
    const { columns, rows } = result;
    if (!columns || !columns.length) return '<div class="sim-empty">No results returned.</div>';
    const MAX_ROWS = compact ? 5 : 200;
    const displayRows = rows.slice(0, MAX_ROWS);
    const statusColors = { '200':'var(--accent-green)','404':'var(--accent-orange)','500':'var(--accent-red)','403':'var(--accent-red)','301':'var(--accent-yellow)','403':'var(--accent-red)' };
    const severityColors = { 'critical':'var(--accent-red)','high':'var(--accent-red)','warn':'var(--accent-yellow)','info':'var(--accent-green)' };

    let html = '<div class="result-meta">'+rows.length+' row'+(rows.length!==1?'s':'')+' · '+columns.length+' field'+(columns.length!==1?'s':'')+(rows.length>MAX_ROWS?' · showing first '+MAX_ROWS:'')+'</div>';
    html += '<div class="result-scroll"><table class="result-table"><thead><tr>';
    columns.forEach(c => { html += '<th>'+escH(c)+'</th>'; });
    html += '</tr></thead><tbody>';
    displayRows.forEach(row => {
      html += '<tr>';
      row.forEach((cell,i) => {
        const col = columns[i].toLowerCase();
        let cls='', style='';
        const cellStr = String(cell);
        if (col==='status') {
          style='color:'+( statusColors[cellStr]||'var(--text-primary)');
          cls = cellStr.startsWith('2')?'cell-ok':cellStr.startsWith('4')||cellStr.startsWith('5')?'cell-err':'cell-warn';
        } else if (col==='severity') { style='color:'+(severityColors[cellStr.toLowerCase()]||'var(--text-primary)'); }
        else if (col==='method') { style='color:var(--accent-cyan);font-weight:600'; }
        else if (col==='user'&&cellStr!=='-'&&cellStr!=='') { style='color:var(--accent-purple)'; }
        else if (col==='host'||col==='hostname') { style='color:var(--accent-orange)'; }
        else if (col==='bytes'||col==='total_bytes'||col==='kb'||col==='size'||col.endsWith('_bytes')) { style='color:var(--accent-yellow)'; }
        else if (col==='count'||col==='eventcount'||col==='dc'||col==='unique_users') { style='color:var(--accent-cyan);font-weight:700'; }
        else if (col==='percent') { style='color:var(--accent-green)'; }
        else if (col==='action') {
          const a=cellStr.toLowerCase();
          style='color:'+(a==='success'?'var(--accent-green)':a==='error'?'var(--accent-red)':a==='forbidden'?'var(--accent-red)':a==='not_found'?'var(--accent-yellow)':'var(--accent-yellow)');
        }
        else if (col==='uri'||col==='path') { style='color:var(--accent-green);font-family:var(--font-mono)'; }
        else if (col==='src_ip'||col==='client_ip') { style='color:var(--text-secondary);font-family:var(--font-mono)'; }
        else if (col==='group'||col==='role'||col==='dept'||col==='env'||col==='region') { style='color:var(--accent-purple)'; }
        else if (col==='owner') { style='color:var(--accent-orange)'; }
        else if (col.includes('delta')||col.includes('accum')||col.includes('total')||col.includes('sum')) { style='color:var(--accent-yellow);font-weight:600'; }
        else if (col.includes('avg')||col.includes('stdev')||col.includes('var')) { style='color:var(--accent-blue)'; }
        else if (col.includes('max')||col.includes('min')) { style='color:var(--accent-cyan)'; }
        else if (col==='label') { style='color:var(--text-secondary)'; }
        
        if (cellStr==='true') style='color:var(--accent-green);font-weight:600';
        if (cellStr==='false') style='color:var(--accent-red)';
        html += '<td class="'+cls+'" style="'+style+'">'+escH(cellStr)+'</td>';
      });
      html += '</tr>';
    });
    html += '</tbody></table></div>';
    return html;
  }

  
  function renderTrace(trace) {
    if (!trace || !trace.length) return '';
    let html = '<div class="trace-wrap">';
    trace.forEach((step, i) => {
      const { label, cmd, data } = step;
      const isFinal = i === trace.length - 1;
      html += `<div class="trace-step ${isFinal?'trace-final':''}">
        <div class="trace-step-header">
          <span class="trace-step-num">${i === 0 ? '⬡' : i}</span>
          <span class="trace-step-label">${escH(label)}</span>
          <span class="trace-step-count">${data.total} row${data.total!==1?'s':''}</span>
          ${data.total > 8 ? '<span class="trace-step-note">showing 8</span>' : ''}
        </div>
        <div class="trace-cmd"><code>${escH(cmd)}</code></div>`;
      if (data.columns.length) {
        html += renderTable({ columns: data.columns, rows: data.rows }, true);
      } else {
        html += '<div class="sim-empty" style="padding:10px 16px;font-size:11px">No events at this stage</div>';
      }
      if (i < trace.length - 1) {
        html += '<div class="trace-arrow">↓ pipe</div>';
      }
      html += '</div>';
    });
    html += '</div>';
    return html;
  }

  function escH(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  
  function buildSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    let html = `<div class="sidebar-search-wrap"><input class="sidebar-search" id="sidebar-search" placeholder="search commands…" oninput="window.filterSidebar(this.value)" autocomplete="off" spellcheck="false"></div>`;
    categories.forEach(cat => {
      const cmds = Object.values(commands).filter(c=>c.tag===cat.id);
      if (!cmds.length) return;
      html += `<div class="sidebar-group" data-cat="${cat.id}">`;
      html += `<div class="sidebar-cat"><span style="color:${cat.color}">${cat.icon}</span><span>${cat.label}</span></div>`;
      cmds.forEach(c => {
        html += `<button class="sidebar-item" id="sb-${c.name}" onclick="window.showCommand('${c.name}')" data-cmd="${c.name}">
          <span class="sidebar-icon">${c.icon}</span>
          <span class="sidebar-name">${c.name}</span>
          <span class="sidebar-tag ${c.tagClass}">${c.tagLabel}</span>
        </button>`;
      });
      html += '</div>';
    });
    sidebar.innerHTML = html;
  }

  window.filterSidebar = function(val) {
    val = val.toLowerCase();
    document.querySelectorAll('.sidebar-item').forEach(btn => {
      const name = btn.dataset.cmd.toLowerCase();
      btn.style.display = (!val||name.includes(val)) ? '' : 'none';
    });
    document.querySelectorAll('.sidebar-group').forEach(g => {
      const vis = [...g.querySelectorAll('.sidebar-item')].some(b=>b.style.display!=='none');
      g.style.display = vis?'':'none';
    });
  };

  function buildHomeGrid() {
    const grid = document.getElementById('home-grid');
    if (!grid) return;
    let html = '';
    categories.forEach(cat => {
      const cmds = Object.values(commands).filter(c=>c.tag===cat.id);
      if (!cmds.length) return;
      html += `<div class="grid-cat-label" style="color:${cat.color}">${cat.icon} ${cat.label}</div>`;
      cmds.forEach(c => {
        html += `<div class="cmd-card" onclick="window.showCommand('${c.name}')">
          <div class="cmd-card-icon">${c.icon}</div>
          <div class="cmd-card-body">
            <div class="cmd-card-name">${c.name}</div>
            <div class="cmd-card-sub">${c.subtitle}</div>
          </div>
          <span class="sidebar-tag ${c.tagClass}">${c.tagLabel}</span>
        </div>`;
      });
    });
    grid.innerHTML = html;
  }

  
  window.showCommand = function(cmdName) {
    const cmd = commands[cmdName];
    if (!cmd) return;
    activeCmd = cmdName;
    document.querySelectorAll('.sidebar-item').forEach(b => b.classList.remove('active'));
    const btn = document.getElementById('sb-'+cmdName);
    if (btn) btn.classList.add('active');
    const gridWrap = document.getElementById('home-grid-wrap');
    if (gridWrap) gridWrap.style.display = 'none';
    const ca = document.getElementById('content-area');

    let optHtml = '<table class="opts-table"><tbody>';
    cmd.options.forEach(o => {
      optHtml += `<tr><td><code>${escH(o.opt)}</code></td><td>${escH(o.desc)}</td></tr>`;
    });
    optHtml += '</tbody></table>';

    let tipsHtml = '';
    if (cmd.tips&&cmd.tips.length) {
      tipsHtml = '<div class="tips-block">';
      cmd.tips.forEach(t => { tipsHtml += `<div class="tip-item">${t.text}</div>`; });
      tipsHtml += '</div>';
    }

    let syntaxHtml = cmd.syntax.map(s=>`<div class="syntax-line" onclick="window.loadSyntax(this)" data-q="${escH(s)}">${highlightSPL(s)}</div>`).join('');
    let presetsHtml = cmd.presets.map(p=>
      `<button class="preset-btn" onclick="window.loadPreset('${encodeURIComponent(p.query)}')">${escH(p.label)}</button>`
    ).join('');

    ca.innerHTML = `
      <div class="cmd-panel">
        <div class="cmd-header">
          <div class="cmd-header-left">
            <span class="cmd-big-icon">${cmd.icon}</span>
            <div>
              <h2 class="cmd-title">| ${cmd.name}</h2>
              <p class="cmd-subtitle">${cmd.subtitle}</p>
            </div>
          </div>
          <div class="cmd-badges">${cmd.badges.map(b=>`<span class="badge">${b}</span>`).join('')}</div>
        </div>

        <div class="section-tabs" id="section-tabs">
          <button class="tab active" onclick="window.switchTab('desc',this)">Description</button>
          <button class="tab" onclick="window.switchTab('syntax',this)">Syntax</button>
          <button class="tab" onclick="window.switchTab('opts',this)">Options</button>
          <button class="tab" onclick="window.switchTab('tips',this)">Exam Tips</button>
          <button class="tab" onclick="window.switchTab('sim',this)">▶ Simulate</button>
        </div>

        <div class="tab-panel active" id="tab-desc">
          <div class="desc-text">${cmd.description}</div>
        </div>
        <div class="tab-panel" id="tab-syntax">
          <p class="section-hint">Click any syntax line to load it into the simulator.</p>
          <div class="syntax-block">${syntaxHtml}</div>
        </div>
        <div class="tab-panel" id="tab-opts">
          ${optHtml}
        </div>
        <div class="tab-panel" id="tab-tips">
          ${tipsHtml||'<div class="sim-empty">No exam tips for this command.</div>'}
        </div>
        <div class="tab-panel" id="tab-sim">
          <div class="sim-wrap">
            <div class="sim-toolbar">
              <div class="sim-presets">${presetsHtml}</div>
              <div class="sim-actions">
                <button class="sim-trace-btn ${traceMode?'active':''}" id="trace-btn" onclick="window.toggleTrace()" title="Show step-by-step pipeline trace">⬡ Trace</button>
                <button class="sim-run-btn" onclick="window.runSim()">▶ Run</button>
                <button class="sim-clear-btn" onclick="window.clearSim()">✕ Clear</button>
              </div>
            </div>
            <div class="sim-terminal">
              <div class="terminal-dots"><span></span><span></span><span></span></div>
              <div class="terminal-label">SPL Query — Ctrl+Enter to run</div>
              <textarea class="sim-input" id="sim-input" spellcheck="false" autocomplete="off" autocorrect="off">${cmd.defaultQuery}</textarea>
            </div>
            <div class="sim-output" id="sim-output">
              <div class="sim-empty">← Select a preset or type a query, then click ▶ Run</div>
            </div>
          </div>
        </div>
      </div>`;

    const textarea = document.getElementById('sim-input');
    if (textarea) {
      textarea.addEventListener('keydown', e => {
        if ((e.ctrlKey||e.metaKey) && e.key==='Enter') { e.preventDefault(); window.runSim(); }
      });
    }
  };

  window.toggleTrace = function() {
    traceMode = !traceMode;
    const btn = document.getElementById('trace-btn');
    if (btn) btn.classList.toggle('active', traceMode);
  };

  window.switchTab = function(tab, btn) {
    document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
    const panel = document.getElementById('tab-'+tab);
    if (panel) panel.classList.add('active');
    if (btn) btn.classList.add('active');
  };

  window.loadSyntax = function(el) {
    const q = el.dataset.q;
    const ta = document.getElementById('sim-input');
    if (!ta) return;
    ta.value = q;
    document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
    const simTab = document.querySelector('[onclick*="\'sim\'"]');
    const simPanel = document.getElementById('tab-sim');
    if (simTab) simTab.classList.add('active');
    if (simPanel) simPanel.classList.add('active');
  };

  window.loadPreset = function(encoded) {
    const q = decodeURIComponent(encoded);
    const ta = document.getElementById('sim-input');
    if (ta) ta.value = q;
    document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
    const simTab = document.querySelector('[onclick*="\'sim\'"]');
    const simPanel = document.getElementById('tab-sim');
    if (simTab) simTab.classList.add('active');
    if (simPanel) simPanel.classList.add('active');
    window.runSim();
  };

  window.runSim = function() {
    const ta = document.getElementById('sim-input');
    const out = document.getElementById('sim-output');
    if (!ta||!out) return;
    const query = ta.value.trim();
    if (!query) { out.innerHTML='<div class="sim-empty">Enter a query above.</div>'; return; }
    out.innerHTML = '<div class="sim-loading"><div class="spin"></div> Running query…</div>';
    setTimeout(() => {
      try {
        const result = runQuery(query, traceMode);
        if (traceMode && result.trace && result.trace.length > 1) {
          out.innerHTML = renderTrace(result.trace);
        } else {
          out.innerHTML = renderTable(result, false);
        }
      } catch(e) {
        out.innerHTML = '<div class="sim-error">⚠ Query error: '+escH(e.message)+'<br><small style="opacity:0.6">'+escH(e.stack||'')+'</small></div>';
      }
    }, 60);
  };

  window.clearSim = function() {
    const ta = document.getElementById('sim-input');
    const out = document.getElementById('sim-output');
    if (ta) ta.value = '';
    if (out) out.innerHTML = '<div class="sim-empty">← Query cleared.</div>';
  };

  
  function startLiveFeed() {
    const feed = document.getElementById('live-feed-body');
    if (!feed) return;
    let idx = 0;
    const statusClass = s => s>=500?'fe-err':s>=400?'fe-warn':s===301?'fe-redir':'fe-ok';
    const render = () => {
      const e = events[idx % events.length];
      const row = document.createElement('div');
      row.className = 'feed-row';
      row.innerHTML = `<span class="fe-time">${e._time.split(' ')[1]}</span>
        <span class="fe-host">${e.host}</span>
        <span class="fe-method">${e.method}</span>
        <span class="fe-uri">${e.uri}</span>
        <span class="fe-status ${statusClass(e.status)}">${e.status}</span>
        <span class="fe-bytes">${e.bytes.toLocaleString()}b</span>
        <span class="fe-user">${e.user}</span>`;
      feed.prepend(row);
      while (feed.children.length > 9) feed.removeChild(feed.lastChild);
      idx++;
    };
    render();
    feedTimer = setInterval(render, 1400);
  }

  
  document.addEventListener('DOMContentLoaded', () => {
    buildSidebar();
    buildHomeGrid();
    startLiveFeed();
    const firstCmd = Object.keys(commands)[0];
    if (firstCmd) window.showCommand(firstCmd);
  });

})();