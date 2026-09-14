(function () {
  'use strict';

  const D        = window.ADMIN_DATA;
  const topics   = D.topics;
  const categories = D.categories;
  const FEED     = window.FEED_LINES;

  let feedTimer  = null;
  let feedIdx    = 0;

  const STEP_ORDER = [
    'forwarder_uf','forwarder_hf','hec','inputs_conf','outputs_conf',
    'props_conf','transforms_conf','indexer','indexes_conf','search_head',
    'deployment_server','cluster_manager','config_layering','auth_conf','ports',
    'installation_hardening','data_pipeline','server_conf','builtin_indexes',
    'licensing_detail','dist_search_detail','apps_roles','monitoring_console',
    'windows_inputs','cli_btool','uf_config_map','hf_config_map',
    'indexer_config_map','sh_config_map','ds_config_map','cm_config_map',
    'conf_file_matrix','priority_all_contexts','spl_reference','topologies',
    'monitor_wildcards','load_balancing_ack','metadata_fields',
    'saml_radius_duo_deep','roles_deep_dive','bucket_lifecycle_detail',
    'indexes_creation_reasons','detection_sysmon_windows',
    'operational_practices','web_conf_limits','exam_critical_facts'
  ];

  function escH(s) {
    return String(s)
      .replace(/&/g,'&amp;')
      .replace(/</g,'&lt;')
      .replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;');
  }

  function highlightConf(text) {
    const lines = text.split('\n');
    return lines.map(line => {
      if (/^\s*#/.test(line)) return '<span class="cf-comment">' + escH(line) + '</span>';
      const stanzaM = line.match(/^(\[)([^\]]+)(\])(.*)$/);
      if (stanzaM) return '<span class="cf-stanza">' + escH('[' + stanzaM[2] + ']') + '</span>' + escH(stanzaM[4] || '');
      const kvM = line.match(/^(\s*)([^\s=]+)(\s*=\s*)(.*)$/);
      if (kvM) {
        const val = kvM[4].trim();
        let valSpan;
        if (val === 'true' || val === '1') valSpan = '<span class="cf-bool-t">' + escH(val) + '</span>';
        else if (val === 'false' || val === '0') valSpan = '<span class="cf-bool-f">' + escH(val) + '</span>';
        else if (/^\$SPLUNK/.test(val) || /^\//.test(val) || /^https?:\/\//.test(val)) valSpan = '<span class="cf-path">' + escH(val) + '</span>';
        else if (/^\d+$/.test(val)) valSpan = '<span class="cf-num">' + escH(val) + '</span>';
        else valSpan = '<span class="cf-val">' + escH(val) + '</span>';
        return escH(kvM[1]) + '<span class="cf-key">' + escH(kvM[2]) + '</span>' + '<span class="cf-eq">' + escH(kvM[3]) + '</span>' + valSpan;
      }
      return escH(line);
    }).join('\n');
  }

  function analyzeConf(text) {
    const findings = [];
    const lines = text.split('\n');
    let currentStanza = null;
    let hasHomePath = false, hasColdPath = false, hasThawedPath = false;
    let isIndexDef = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      const stanzaM = trimmed.match(/^\[([^\]]+)\]$/);
      if (stanzaM) {
        if (isIndexDef) {
          if (!hasHomePath)   findings.push({type:'err',  msg:'Index [' + currentStanza + '] missing required: homePath'});
          if (!hasColdPath)   findings.push({type:'err',  msg:'Index [' + currentStanza + '] missing required: coldPath'});
          if (!hasThawedPath) findings.push({type:'err',  msg:'Index [' + currentStanza + '] missing required: thawedPath'});
        }
        currentStanza = stanzaM[1];
        isIndexDef = false;
        hasHomePath = hasColdPath = hasThawedPath = false;

        if (/^(security|main|windows|linux|network|custom|hec|archive|syslog)$/.test(currentStanza)) {
          isIndexDef = true;
          findings.push({type:'info', msg:'Index definition detected: [' + currentStanza + ']'});
        } else if (/^tcpout/.test(currentStanza))          findings.push({type:'info', msg:'Output group stanza: [' + currentStanza + ']'});
        else if (/^monitor:/.test(currentStanza))           findings.push({type:'info', msg:'File monitor stanza: [' + currentStanza + ']'});
        else if (/^(tcp|udp):\/\//.test(currentStanza))     findings.push({type:'info', msg:'Network input stanza: [' + currentStanza + ']'});
        else if (/^WinEventLog:/.test(currentStanza))       findings.push({type:'info', msg:'Windows Event Log stanza: [' + currentStanza + ']'});
        else if (/^clustering$/.test(currentStanza))        findings.push({type:'info', msg:'Cluster configuration stanza detected'});
        else if (/^target-broker:/.test(currentStanza))     findings.push({type:'info', msg:'Deployment client stanza - forwarder will poll deployment server'});
        else if (/^serverClass:/.test(currentStanza))       findings.push({type:'info', msg:'Server class stanza: [' + currentStanza + ']'});
        else if (/^authentication$/.test(currentStanza))    findings.push({type:'info', msg:'Authentication configuration stanza detected'});
        else if (/^distributedSearch/.test(currentStanza))  findings.push({type:'info', msg:'Distributed search stanza: [' + currentStanza + ']'});
        else if (/^role_/.test(currentStanza))              findings.push({type:'info', msg:'Custom role definition: [' + currentStanza + ']'});
        else if (/^http:\/\//.test(currentStanza))          findings.push({type:'info', msg:'HEC token stanza - runs on port 8088'});
        continue;
      }

      const kvM = trimmed.match(/^([^\s=]+)\s*=\s*(.*)$/);
      if (!kvM) continue;
      const key = kvM[1].toLowerCase();
      const val = kvM[2].trim();

      if (key === 'homepath')   hasHomePath   = true;
      if (key === 'coldpath')   hasColdPath   = true;
      if (key === 'thawedpath') hasThawedPath = true;

      if (key === 'frozentimeperiodinsecs') {
        const secs = parseInt(val, 10);
        if (!isNaN(secs)) findings.push({type:'ok', msg:'frozenTimePeriodInSecs = ' + val + ' (' + Math.round(secs/86400) + ' days retention)'});
      }
      if (key === 'mode') {
        if (val === 'manager')    findings.push({type:'ok', msg:'Cluster mode = manager (Cluster Manager node)'});
        if (val === 'peer')       findings.push({type:'ok', msg:'Cluster mode = peer (Indexer cluster peer)'});
        if (val === 'searchhead') findings.push({type:'ok', msg:'Cluster mode = searchhead'});
      }
      if (key === 'maxtotaldatasizemb') {
        const gb = Math.round(parseInt(val,10)/1024);
        findings.push({type:'ok', msg:'maxTotalDataSizeMB = ' + val + ' (~' + gb + ' GB max index size)'});
      }
      if (key === 'enabledataintegritycontrol' && val === '1') findings.push({type:'ok', msg:'Data integrity control enabled - raw event hashing active'});
      if (key.startsWith('sedcmd-')) findings.push({type:'ok', msg:'SEDCMD: ' + key + ' - raw data will be modified at index time'});
      if (key === 'should_linemerge') {
        if (val === 'false') findings.push({type:'ok',   msg:'SHOULD_LINEMERGE = false - single-line mode (efficient)'});
        if (val === 'true')  findings.push({type:'warn', msg:'SHOULD_LINEMERGE = true - multiline merge active. Ensure LINE_BREAKER is set.'});
      }
      if (key === 'line_breaker') findings.push({type:'ok', msg:'LINE_BREAKER defined: ' + val});
      if (key === 'authtype') {
        if (val === 'LDAP')   findings.push({type:'ok', msg:'Authentication type = LDAP - ensure group mappings are configured'});
        if (val === 'SAML')   findings.push({type:'ok', msg:'Authentication type = SAML - inherently supports SSO and MFA'});
        if (val === 'Splunk') findings.push({type:'ok', msg:'Authentication type = native Splunk'});
      }
      if (key === 'failopen') {
        if (val === 'true')  findings.push({type:'warn', msg:'failOpen = true - Duo MFA bypassed if Duo service is unavailable'});
        if (val === 'false') findings.push({type:'ok',   msg:'failOpen = false - Duo MFA always enforced'});
      }
      if (key === 'sslenabled' && val === '1') findings.push({type:'ok', msg:'SSL/TLS enabled for LDAP (LDAPS)'});
      if (key === 'phonehomeintervalsecs') findings.push({type:'ok', msg:'phoneHomeIntervalInSecs = ' + val + 's (forwarder check-in interval)'});
      if (key === 'server' && currentStanza && /^tcpout/.test(currentStanza)) {
        const servers = val.split(',').map(s=>s.trim()).filter(Boolean);
        if (servers.length > 1) findings.push({type:'ok', msg:'Load balancing configured across ' + servers.length + ' indexers'});
        else findings.push({type:'ok', msg:'Forwarding to: ' + val});
      }
      if (key === 'disabled' && val === '0') findings.push({type:'ok',   msg:'Input is enabled (disabled = 0)'});
      if (key === 'disabled' && val === '1') findings.push({type:'warn', msg:'Input is disabled (disabled = 1) - no data will be collected'});
      if (key === 'replication_factor') findings.push({type:'ok', msg:'replication_factor = ' + val + ' - ' + val + ' copies of each bucket maintained'});
      if (key === 'search_factor')      findings.push({type:'ok', msg:'search_factor = ' + val + ' - ' + val + ' searchable copies required'});
      if (key === 'followtail' && val === 'true') findings.push({type:'warn', msg:'followTail = true - only NEW data after Splunk start will be indexed. Existing content skipped.'});
      if (key === 'charset') findings.push({type:'ok', msg:'CHARSET = ' + val + ' - character encoding set for this source'});
    }

    if (isIndexDef) {
      if (!hasHomePath)   findings.push({type:'err', msg:'Index [' + currentStanza + '] missing required: homePath'});
      if (!hasColdPath)   findings.push({type:'err', msg:'Index [' + currentStanza + '] missing required: coldPath'});
      if (!hasThawedPath) findings.push({type:'err', msg:'Index [' + currentStanza + '] missing required: thawedPath'});
    }

    if (!findings.length) findings.push({type:'ok', msg:'Configuration parsed - no issues detected'});
    return findings;
  }

  function buildFullArchSvg() {
    const svgs = STEP_ORDER
      .filter(k => topics[k] && topics[k].archSvg)
      .map(k => {
        const t = topics[k];
        const stepNum = STEP_ORDER.indexOf(k) + 1;
        return `<div class="full-arch-step">
          <div class="full-arch-step-label">
            <span class="full-arch-step-num">${stepNum}</span>
            <span class="full-arch-step-name">${escH(t.name)}</span>
            <span class="full-arch-step-sub">${escH(t.subtitle.replace(/^Step \d+:\s*/,''))}</span>
          </div>
          <div class="full-arch-svg-wrap">${t.archSvg}</div>
        </div>`;
      });
    return svgs.join('');
  }

  function buildSidebar() {
    const sb = document.getElementById('sidebar');
    if (!sb) return;

    let html = '<div class="sidebar-search-wrap"><input class="sidebar-search" placeholder="filter topics..." id="sidebar-search" oninput="window.filterSidebar(this.value)"></div>';

    html += `<div class="sidebar-group" id="sg-full-arch">
      <button class="sidebar-item sidebar-item-full-arch" id="sb-full_arch" data-key="full_arch" onclick="window.showFullArch()">
        <span class="sidebar-icon"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="7" height="7" rx="1"/><rect x="11" y="2" width="7" height="7" rx="1"/><rect x="2" y="11" width="7" height="7" rx="1"/><rect x="11" y="11" width="7" height="7" rx="1"/></svg></span>
        <span class="sidebar-name">Full Architecture</span>
        <span class="sidebar-tag tag-full-arch">ALL</span>
      </button>
    </div>
    <div class="sidebar-divider"></div>
    <div class="sidebar-steps-label">Steps</div>`;

    const ordered = STEP_ORDER.filter(k => topics[k]);
    ordered.forEach((key, idx) => {
      const t = topics[key];
      const stepNum = idx + 1;
      html += `<button class="sidebar-item sidebar-item-step" id="sb-${escH(key)}" data-key="${escH(key)}" onclick="window.showTopic('${escH(key)}')">
        <span class="sidebar-step-num">${stepNum}</span>
        <span class="sidebar-icon">${t.svgIcon}</span>
        <span class="sidebar-name">${escH(t.name)}</span>
        <span class="sidebar-tag ${t.tagClass}">${escH(t.tagLabel)}</span>
      </button>`;
    });

    sb.innerHTML = html;
  }

  window.filterSidebar = function(q) {
    const lower = q.toLowerCase();
    document.querySelectorAll('.sidebar-item-step').forEach(btn => {
      const t = topics[btn.dataset.key];
      if (!t) return;
      const match = !lower || t.name.toLowerCase().includes(lower) || t.subtitle.toLowerCase().includes(lower) || t.category.toLowerCase().includes(lower);
      btn.style.display = match ? '' : 'none';
    });
    const fullArchBtn = document.getElementById('sb-full_arch');
    if (fullArchBtn) {
      fullArchBtn.style.display = !lower || 'full architecture'.includes(lower) ? '' : 'none';
    }
  };

  function buildHomeGrid() {
    const grid = document.getElementById('home-grid');
    if (!grid) return;
    let html = '';
    const ordered = STEP_ORDER.filter(k => topics[k]);
    ordered.forEach((key, idx) => {
      const t = topics[key];
      const stepNum = idx + 1;
      html += `<div class="cmd-card" onclick="window.showTopic('${escH(key)}')">
        <div class="cmd-card-step">${stepNum}</div>
        <div class="cmd-card-icon">${t.svgIcon}</div>
        <div class="cmd-card-body">
          <div class="cmd-card-name">${escH(t.name)}</div>
          <div class="cmd-card-sub">${escH(t.subtitle.replace(/^Step \d+:\s*/,''))}</div>
        </div>
        <span class="sidebar-tag ${t.tagClass}">${escH(t.tagLabel)}</span>
      </div>`;
    });
    grid.innerHTML = html;
  }

  window.showFullArch = function() {
    document.querySelectorAll('.sidebar-item').forEach(b => b.classList.remove('active'));
    const sbBtn = document.getElementById('sb-full_arch');
    if (sbBtn) sbBtn.classList.add('active');

    const ca = document.getElementById('content-area');
    if (!ca) return;

    ca.innerHTML = `
      <div class="cmd-panel">
        <div class="cmd-header">
          <div class="cmd-header-left">
            <span class="cmd-big-icon"><svg viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="7" height="7" rx="1"/><rect x="11" y="2" width="7" height="7" rx="1"/><rect x="2" y="11" width="7" height="7" rx="1"/><rect x="11" y="11" width="7" height="7" rx="1"/></svg></span>
            <div>
              <h2 class="cmd-title">Full Architecture</h2>
              <p class="cmd-subtitle">All 15 steps in order - complete Splunk enterprise deployment</p>
            </div>
          </div>
          <div class="cmd-badges">
            <span class="badge">15 Steps</span>
            <span class="badge">Complete Reference</span>
          </div>
        </div>
        <div class="full-arch-container">
          ${buildFullArchSvg()}
        </div>
      </div>`;
  };

  window.showTopic = function(key) {
    const topic = topics[key];
    if (!topic) return;

    document.querySelectorAll('.sidebar-item').forEach(b => b.classList.remove('active'));
    const sbBtn = document.getElementById('sb-' + key);
    if (sbBtn) sbBtn.classList.add('active');

    const ca = document.getElementById('content-area');
    if (!ca) return;

    let optHtml = '<table class="opts-table"><tbody>';
    (topic.options || []).forEach(o => {
      optHtml += `<tr><td><code>${escH(o.opt)}</code></td><td>${escH(o.desc)}</td></tr>`;
    });
    optHtml += '</tbody></table>';

    let tipsHtml = '';
    if (topic.tips && topic.tips.length) {
      tipsHtml = '<div class="tips-block">';
      topic.tips.forEach(t => { tipsHtml += `<div class="tip-item">${t.text}</div>`; });
      tipsHtml += '</div>';
    }

    let stanzasHtml = (topic.stanzas || []).map(s =>
      `<div class="stanza-line" onclick="window.loadStanza(this)" data-q="${escH(s)}">${highlightConf(s)}</div>`
    ).join('');

    let presetsHtml = (topic.presets || []).map(p =>
      `<button class="preset-btn" onclick="window.loadPreset('${encodeURIComponent(p.conf)}')">${escH(p.label)}</button>`
    ).join('');

    const archTabBtn = topic.archSvg
      ? `<button class="tab" onclick="window.switchTab('arch',this)">Architecture</button>`
      : '';
    const archTabPanel = topic.archSvg
      ? `<div class="tab-panel" id="tab-arch"><div class="arch-tab-wrap">${topic.archSvg}</div></div>`
      : '';

    const stepNum = STEP_ORDER.indexOf(key) + 1;

    ca.innerHTML = `
      <div class="cmd-panel">
        <div class="cmd-header">
          <div class="cmd-header-left">
            ${stepNum > 0 ? `<span class="cmd-step-badge">${stepNum}</span>` : ''}
            <span class="cmd-big-icon">${topic.svgIcon}</span>
            <div>
              <h2 class="cmd-title">${escH(topic.name)}</h2>
              <p class="cmd-subtitle">${escH(topic.subtitle)}</p>
            </div>
          </div>
          <div class="cmd-badges">${(topic.badges||[]).map(b=>`<span class="badge">${escH(b)}</span>`).join('')}</div>
        </div>
        <div class="section-tabs" id="section-tabs">
          <button class="tab active" onclick="window.switchTab('desc',this)">Description</button>
          <button class="tab" onclick="window.switchTab('stanzas',this)">Stanzas</button>
          <button class="tab" onclick="window.switchTab('opts',this)">Key Settings</button>
          <button class="tab" onclick="window.switchTab('tips',this)">Exam Tips</button>
          ${archTabBtn}
          <button class="tab" onclick="window.switchTab('sim',this)">Analyze</button>
        </div>
        <div class="tab-panel active" id="tab-desc">
          <div class="desc-text">${topic.description}</div>
        </div>
        <div class="tab-panel" id="tab-stanzas">
          <p class="section-hint">Click any stanza block to load it into the analyzer.</p>
          <div class="stanza-block">${stanzasHtml}</div>
        </div>
        <div class="tab-panel" id="tab-opts">${optHtml}</div>
        <div class="tab-panel" id="tab-tips">${tipsHtml || '<div class="sim-empty">No exam tips for this topic.</div>'}</div>
        ${archTabPanel}
        <div class="tab-panel" id="tab-sim">
          <div class="sim-wrap">
            <div class="sim-toolbar">
              <div class="sim-presets">${presetsHtml}</div>
              <div class="sim-actions">
                <button class="sim-run-btn" onclick="window.runSim()">Analyze</button>
                <button class="sim-clear-btn" onclick="window.clearSim()">Clear</button>
              </div>
            </div>
            <div class="sim-terminal">
              <div class="terminal-dots"><span></span><span></span><span></span></div>
              <div class="terminal-label">${escH(topic.name)} config - Ctrl+Enter to analyze</div>
              <textarea class="sim-input" id="sim-input" spellcheck="false" autocomplete="off" autocorrect="off">${escH(topic.defaultConf || '')}</textarea>
            </div>
            <div class="sim-output" id="sim-output">
              <div class="sim-empty">Select a preset or type a config stanza, then click Analyze</div>
            </div>
          </div>
        </div>
      </div>`;

    const textarea = document.getElementById('sim-input');
    if (textarea) {
      textarea.addEventListener('keydown', e => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); window.runSim(); }
      });
    }
  };

  window.switchTab = function(tab, btn) {
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    const panel = document.getElementById('tab-' + tab);
    if (panel) panel.classList.add('active');
    if (btn) btn.classList.add('active');
  };

  window.loadStanza = function(el) {
    const ta = document.getElementById('sim-input');
    if (!ta) return;
    ta.value = el.dataset.q;
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    const simTab = document.querySelector('[onclick*="\'sim\'"]');
    const simPanel = document.getElementById('tab-sim');
    if (simTab) simTab.classList.add('active');
    if (simPanel) simPanel.classList.add('active');
  };

  window.loadPreset = function(encoded) {
    const ta = document.getElementById('sim-input');
    if (ta) ta.value = decodeURIComponent(encoded);
    document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    const simTab = document.querySelector('[onclick*="\'sim\'"]');
    const simPanel = document.getElementById('tab-sim');
    if (simTab) simTab.classList.add('active');
    if (simPanel) simPanel.classList.add('active');
    window.runSim();
  };

  window.runSim = function() {
    const ta  = document.getElementById('sim-input');
    const out = document.getElementById('sim-output');
    if (!ta || !out) return;
    const conf = ta.value.trim();
    if (!conf) { out.innerHTML = '<div class="sim-empty">Enter a configuration stanza above.</div>'; return; }
    out.innerHTML = '<div class="sim-loading"><div class="spin"></div> Analyzing configuration...</div>';
    setTimeout(() => {
      try {
        const findings = analyzeConf(conf);
        const errors = findings.filter(f => f.type === 'err').length;
        const warns  = findings.filter(f => f.type === 'warn').length;
        let statusClass = 'ok', statusText = 'VALID';
        if (errors)     { statusClass = 'err';  statusText = errors + ' ERROR' + (errors > 1 ? 'S' : ''); }
        else if (warns) { statusClass = 'warn'; statusText = warns  + ' WARNING' + (warns > 1 ? 'S' : ''); }
        let html = `<div class="conf-result-header"><span>Analysis complete - ${findings.length} finding${findings.length !== 1 ? 's' : ''}</span><span class="${statusClass}">${statusText}</span></div>`;
        for (const f of findings) {
          const cls    = f.type === 'err' ? 'cf-err' : f.type === 'warn' ? 'cf-warn' : f.type === 'info' ? 'cf-info' : 'cf-ok';
          const prefix = f.type === 'err' ? 'x ' : f.type === 'warn' ? '! ' : f.type === 'info' ? '> ' : 'v ';
          html += `<div class="conf-finding"><span class="${cls}">${prefix}${escH(f.msg)}</span></div>`;
        }
        html += `<div style="border-top:1px solid var(--border-subtle)"><div class="conf-result-header"><span>Highlighted config</span></div><div class="conf-output">${highlightConf(conf)}</div></div>`;
        out.innerHTML = html;
      } catch(e) {
        out.innerHTML = '<div class="sim-error">Parse error: ' + escH(e.message) + '</div>';
      }
    }, 60);
  };

  window.clearSim = function() {
    const ta  = document.getElementById('sim-input');
    const out = document.getElementById('sim-output');
    if (ta) ta.value = '';
    if (out) out.innerHTML = '<div class="sim-empty">Config cleared.</div>';
  };

  function startLiveFeed() {
    const feed = document.getElementById('live-feed-body');
    if (!feed) return;
    const levelClass = l => l === 'ERROR' ? 'fe-level-error' : l === 'WARN' ? 'fe-level-warn' : 'fe-level-info';
    const now = () => new Date().toTimeString().slice(0, 8);
    const render = () => {
      const e = FEED[feedIdx % FEED.length];
      const row = document.createElement('div');
      row.className = 'feed-row';
      row.innerHTML = `<span class="fe-time">${now()}</span><span class="fe-level ${levelClass(e.level)}">${e.level}</span><span class="fe-component">${escH(e.component)}</span><span class="fe-msg">${escH(e.msg)}</span>`;
      feed.prepend(row);
      while (feed.children.length > 9) feed.removeChild(feed.lastChild);
      feedIdx++;
    };
    render();
    feedTimer = setInterval(render, 1600);
  }

  document.addEventListener('DOMContentLoaded', () => {
    buildSidebar();
    buildHomeGrid();
    startLiveFeed();
    window.showFullArch();
  });

})();