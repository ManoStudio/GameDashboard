// Kept dependency-free so both server-rendered frontends use the same interactions.
function initAdmin() {
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const button = (text, action, style = 'btn secondary small') => {
    const node = document.createElement('button'); node.type = 'button'; node.className = style;
    node.textContent = text; node.addEventListener('click', action); return node;
  };
  let toastTimer;
  function toast(message) {
    let node = $('.toast');
    if (!node) { node = document.createElement('div'); node.className = 'toast'; node.setAttribute('role', 'status'); document.body.append(node); }
    node.textContent = message; node.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => node.hidden = true, 4500);
  }
  try {
    document.documentElement.dataset.theme = localStorage.getItem('game-build-dashboard-theme') === 'light' ? 'light' : 'dark';
  } catch {}
  $$('[data-theme-toggle]').forEach(node => node.addEventListener('click', () => {
    const theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('game-build-dashboard-theme', theme); } catch {}
  }));
  $$('[data-project-selector]').forEach(node => node.addEventListener('change', () => {
    const url = new URL(location.href); url.searchParams.set('project', node.value);
    ['log_project', 'log_version', 'build', 'log'].forEach(key => url.searchParams.delete(key));
    if (['build', 'log'].includes(url.searchParams.get('view'))) url.searchParams.set('view', 'dashboard');
    location.href = url;
  }));
  $$('[data-copy]').forEach(node => node.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(node.dataset.copy); toast('Copied to clipboard'); }
    catch { toast('Unable to copy. Select the value and copy it manually.'); }
  }));
  $$('[data-menu]').forEach(trigger => {
    const menu = document.getElementById(trigger.dataset.menu);
    if (!menu) return;
    menu.setAttribute('popover', 'auto'); document.body.append(menu);
    trigger.setAttribute('aria-expanded', 'false');
    menu.addEventListener('toggle', event => trigger.setAttribute('aria-expanded', String(event.newState === 'open')));
    trigger.addEventListener('click', () => {
      menu.togglePopover();
      const box = trigger.getBoundingClientRect();
      menu.style.left = Math.max(12, Math.min(box.right - menu.offsetWidth, innerWidth - menu.offsetWidth - 12)) + 'px';
      menu.style.top = Math.max(12, Math.min(box.bottom + 5, innerHeight - menu.offsetHeight - 12)) + 'px';
    });
  });
  $$('form[data-confirm]').forEach(form => form.addEventListener('submit', event => {
    if (!confirm(form.dataset.confirm)) event.preventDefault();
  }));

  $$('table[data-build-tools]').forEach(table => {
    const body = table.tBodies[0]; const rows = Array.from(body.rows).filter(row => !row.querySelector('[colspan]'));
    if (!rows.length) return;
    const surface = table.closest('.surface,.panel'); const wrap = table.closest('.table-wrap');
    const toolbar = document.createElement('div'); toolbar.className = 'toolbar build-toolbar'; toolbar.setAttribute('role', 'search'); toolbar.setAttribute('aria-label', 'Search all builds');
    const search = document.createElement('input'); search.className = 'build-search'; search.type = 'search'; search.placeholder = 'Search all builds…'; search.setAttribute('aria-label', 'Search all builds by version, build ID, or commit'); toolbar.append(search);
    const addFilter = (key, label, values, format = value => value) => {
      const select = document.createElement('select'); select.setAttribute('aria-label', 'Filter builds by ' + key.toLowerCase()); select.add(new Option('All ' + label.toLowerCase(), ''));
      values.forEach(value => select.add(new Option(format(value), value))); toolbar.append(select); return select;
    };
    const channels = [...new Set(rows.map(row => row.dataset.channel).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    const statuses = [...new Set(rows.map(row => row.dataset.status).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    const channel = addFilter('Channel', 'Channels', channels, value => ({ dev: 'Development', qa: 'QA', live: 'Live', stable: 'Stable', deprecated: 'Deprecated' }[value.toLowerCase()] || value));
    const status = addFilter('Status', 'Statuses', statuses, value => value === 'ready' ? 'Ready' : value.charAt(0).toUpperCase() + value.slice(1));
    const sort = document.createElement('select'); sort.setAttribute('aria-label', 'Sort builds by date or name');
    [['date-desc', 'Date: newest first'], ['date-asc', 'Date: oldest first'], ['name-asc', 'Name: A–Z'], ['name-desc', 'Name: Z–A']].forEach(([value, label]) => sort.add(new Option(label, value)));
    toolbar.append(sort); surface.insertBefore(toolbar, wrap);
    const summary = document.createElement('div'); summary.className = 'build-result-summary'; summary.setAttribute('role', 'status'); summary.setAttribute('aria-live', 'polite'); surface.insertBefore(summary, wrap);
    const pager = document.createElement('div'); pager.className = 'pager build-pager';
    const count = document.createElement('span'); const actions = document.createElement('div'); actions.className = 'actions';
    const previous = document.createElement('button'); previous.className = 'btn secondary small'; previous.type = 'button'; previous.textContent = 'Previous'; previous.setAttribute('aria-label', 'Previous build results');
    const next = document.createElement('button'); next.className = 'btn secondary small'; next.type = 'button'; next.textContent = 'Next'; next.setAttribute('aria-label', 'Next build results');
    actions.append(previous, next); pager.append(count, actions); surface.append(pager);
    const indexed = rows.map((row, index) => ({ row, index, text: [row.dataset.version, row.dataset.channel, row.dataset.status, row.dataset.date, row.dataset.size, row.cells[2]?.textContent, row.cells[3]?.textContent, row.cells[3]?.title].join(' ').toLocaleLowerCase(), date: Date.parse(row.dataset.date || '') || 0, size: Number(row.dataset.size) || 0, version: row.dataset.version || '' }));
    const versionOrder = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' }); const pageSize = 6; let page = 0;
    function renderBuildResults() {
      const query = search.value.trim().toLocaleLowerCase();
      const matching = indexed.filter(item => (!query || item.text.includes(query)) && (!channel.value || item.row.dataset.channel === channel.value) && (!status.value || item.row.dataset.status === status.value));
      matching.sort((a, b) => {
        let order = 0;
        if (sort.value === 'date-asc') order = a.date - b.date;
        else if (sort.value === 'name-asc') order = versionOrder.compare(a.version, b.version);
        else if (sort.value === 'name-desc') order = versionOrder.compare(b.version, a.version);
        else order = b.date - a.date;
        return order || a.index - b.index;
      });
      const active = !!query || !!channel.value || !!status.value || sort.value !== 'date-desc';
      const pages = Math.max(1, Math.ceil(matching.length / pageSize)); page = Math.min(Math.max(0, page), pages - 1);
      const visible = active ? matching.slice(page * pageSize, (page + 1) * pageSize) : matching.slice(0, pageSize);
      body.replaceChildren(...visible.map(item => item.row));
      if (!matching.length) { const row = body.insertRow(); const cell = row.insertCell(); cell.colSpan = table.tHead.rows[0].cells.length; cell.className = 'empty'; cell.textContent = 'No builds match these filters. Try another search.'; }
      summary.textContent = active ? matching.length + ' matching builds' : 'Showing ' + Math.min(matching.length, pageSize) + (matching.length > pageSize ? ' most recent of ' : ' of ') + matching.length + ' builds';
      count.textContent = matching.length + ' results · Page ' + (page + 1) + ' of ' + pages; pager.hidden = !active || pages <= 1;
      previous.disabled = page === 0; next.disabled = page >= pages - 1;
    }
    search.addEventListener('input', () => { page = 0; renderBuildResults(); });
    [channel, status, sort].forEach(select => select.addEventListener('change', () => { page = 0; renderBuildResults(); }));
    previous.addEventListener('click', () => { page--; renderBuildResults(); }); next.addEventListener('click', () => { page++; renderBuildResults(); });
    renderBuildResults();
  });

  $$('table[data-paginate]').forEach(table => {
    const body = table.tBodies[0]; const rows = Array.from(body.rows).filter(row => !row.querySelector('[colspan]'));
    if (!rows.length) return;
    const surface = table.closest('.surface,.panel'); const toolbar = document.createElement('div'); toolbar.className = 'toolbar';
    const search = document.createElement('input'); search.type = 'search'; search.placeholder = table.dataset.search || 'Search version, build ID, commit…'; search.setAttribute('aria-label', search.placeholder); toolbar.append(search);
    const filters = [];
    ['channel', 'platform', 'status'].forEach(key => {
      const values = [...new Set(rows.map(row => row.dataset[key]).filter(Boolean))]; if (values.length < 2) return;
      const select = document.createElement('select'); select.setAttribute('aria-label', 'Filter ' + key); select.add(new Option('All ' + key + 's', ''));
      values.forEach(value => select.add(new Option(value, value))); filters.push([key, select]); toolbar.append(select);
      select.addEventListener('change', () => { page = 0; render(); });
    });
    if (table.dataset.dateFilter !== undefined) {
      const date = document.createElement('input'); date.type = 'date'; date.setAttribute('aria-label', 'Uploaded date'); date.style.flex = '0 1 160px';
      filters.push(['date', date]); toolbar.append(date); date.addEventListener('change', () => { page = 0; render(); });
    }
    surface.insertBefore(toolbar, table.closest('.table-wrap'));
    const pager = document.createElement('div'); pager.className = 'pager'; const count = document.createElement('span'); const actions = document.createElement('div'); actions.className = 'actions';
    let page = 0; const pageSize = 20;
    const previous = button('Previous', () => { page--; render(); }); const next = button('Next', () => { page++; render(); }); actions.append(previous, next); pager.append(count, actions); surface.append(pager);
    const indexed = rows.map(row => [row, row.textContent.toLowerCase()]);
    function render() {
      const query = search.value.trim().toLowerCase();
      const matching = indexed.filter(([row, text]) => text.includes(query) && filters.every(([key, input]) => !input.value || row.dataset[key] === input.value)).map(([row]) => row);
      const pages = Math.max(1, Math.ceil(matching.length / pageSize)); page = Math.min(Math.max(0, page), pages - 1);
      body.replaceChildren(...matching.slice(page * pageSize, (page + 1) * pageSize));
      if (!matching.length) { const row = body.insertRow(); const cell = row.insertCell(); cell.colSpan = table.tHead.rows[0].cells.length; cell.className = 'empty'; cell.textContent = 'No results match these filters. Try another search.'; }
      count.textContent = `${matching.length} results · Page ${page + 1} of ${pages}`; previous.disabled = page === 0; next.disabled = page >= pages - 1;
    }
    search.addEventListener('input', () => { page = 0; render(); }); render();
  });

  $$('textarea[name="changelog"]').forEach(source => {
    const wrapper = document.createElement('div'); wrapper.className = 'changelog-editor'; source.parentElement.after(wrapper);
    const sections = document.createElement('div'); sections.className = 'changelog-sections'; sections.hidden = true;
    const fields = ['Test Focus', 'Added', 'Changed', 'Fixed', 'Known Issues', 'Notes'].map(title => {
      const label = document.createElement('label'); label.textContent = title; const input = document.createElement('textarea'); input.placeholder = 'One item per line (optional)'; label.append(input); sections.append(label); return [title, input];
    });
    const sync = () => { if (!sections.hidden) source.value = fields.filter(([, input]) => input.value.trim()).map(([title, input]) => '## ' + title + '\n' + input.value.split('\n').filter(line => line.trim()).map(line => '- ' + line.trim()).join('\n')).join('\n\n'); };
    fields.forEach(([, input]) => input.addEventListener('input', sync));
    const toggle = button('Use structured template', () => {
      if (sections.hidden) {
        if (source.value.trim()) { toast('Your existing changelog is preserved. Clear it first to start a structured template.'); return; }
        sections.hidden = false; source.parentElement.hidden = true; toggle.textContent = 'Edit as text';
      } else { sync(); sections.hidden = true; source.parentElement.hidden = false; toggle.textContent = 'Use structured template'; }
    });
    wrapper.append(toggle, sections);
    if (!source.value.trim()) toggle.click();
  });

  let activeUpload = false;
  window.addEventListener('beforeunload', event => { if (activeUpload) { event.preventDefault(); event.returnValue = ''; } });
  $$('form[data-direct-upload]').forEach(form => {
    const input = $('input[type=file]', form); const zone = input.closest('.dropzone');
    const summary = document.createElement('p'); summary.className = 'file-summary'; summary.setAttribute('aria-live', 'polite'); zone.after(summary);
    const format = bytes => bytes >= 1073741824 ? (bytes / 1073741824).toFixed(2) + ' GB' : (bytes / 1048576).toFixed(1) + ' MB';
    const selected = () => { const files = Array.from(input.files); summary.textContent = files.length ? files.map(file => file.name).join(', ') + ' · ' + format(files.reduce((sum, file) => sum + file.size, 0)) : ''; };
    input.addEventListener('change', selected);
    zone.addEventListener('dragover', event => { event.preventDefault(); if (!activeUpload) zone.classList.add('dragging'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('dragging'));
    zone.addEventListener('drop', event => { event.preventDefault(); zone.classList.remove('dragging'); if (!activeUpload) { input.files = event.dataTransfer.files; selected(); } });
    form.addEventListener('submit', async event => {
      event.preventDefault(); if (activeUpload) return;
      const files = Array.from(input.files); if (!files.length) return;
      activeUpload = true; form.classList.add('uploading');
      const data = Object.fromEntries(new FormData(form).entries()); delete data.build;
      const controls = $$('button,input,select,textarea', form); const disabled = controls.map(node => node.disabled); controls.forEach(node => node.disabled = true);
      let progress = $('.upload-progress'); if (progress) progress.remove();
      progress = document.createElement('div'); progress.className = 'upload-progress'; progress.setAttribute('role', 'status');
      const title = document.createElement('strong'); const detail = document.createElement('span'); const bar = document.createElement('progress'); bar.max = 100; bar.setAttribute('aria-label', 'Build upload progress'); progress.append(title, detail, bar); document.body.append(progress);
      const state = (label, message, percent) => { title.textContent = label; detail.textContent = message; if (percent === undefined) bar.removeAttribute('value'); else bar.value = Math.max(0, Math.min(100, percent)); };
      try {
        state('Preparing upload', 'Requesting an upload session…');
        const init = await fetch(form.dataset.initUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...data, files: files.map(file => ({ name: file.name, size: file.size, content_type: file.type || 'application/octet-stream' })) }) });
        if (init.status === 503 && form.dataset.demo === 'true') { activeUpload = false; controls.forEach((node, index) => node.disabled = disabled[index]); HTMLFormElement.prototype.submit.call(form); return; }
        if (!init.ok) throw new Error('Could not prepare the upload. Check your connection, access, and storage configuration.');
        const session = await init.json(); const uploaded = []; const total = files.reduce((sum, file) => sum + file.size, 0); let sent = 0; let started = 0;
        for (let index = 0; index < files.length; index++) {
          const file = files[index]; const target = session.uploads[index];
          state('Validating package', 'Computing checksum for ' + file.name);
          const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
          const hash = Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
          started = performance.now();
          await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest(); xhr.open('PUT', target.upload_url); xhr.setRequestHeader('Content-Type', target.content_type);
            xhr.upload.onprogress = event => { const loaded = Math.min(event.loaded, file.size); const speed = loaded / Math.max((performance.now() - started) / 1000, .1); state('Uploading build', `${format(sent + loaded)} / ${format(total)} · ${format(speed)}/s`, total ? (sent + loaded) / total * 100 : 0); };
            xhr.onload = () => xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error('The package could not be uploaded. Check storage access and retry.'));
            xhr.onerror = () => reject(new Error('Connection interrupted. Check your connection and retry.')); xhr.send(file);
          });
          sent += file.size; uploaded.push({ name: file.name, size: file.size, hash, content_type: target.content_type, object_path: target.object_path });
        }
        state('Processing build', 'Saving manifest and build metadata…');
        const complete = await fetch(form.dataset.completeBase + '/' + session.build_id + '/complete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...data, version: session.version, files: uploaded }) });
        if (!complete.ok) throw new Error('The server could not confirm this build. Check build history before retrying.');
        state('Build ready', 'Upload completed successfully.', 100); activeUpload = false;
        try { sessionStorage.setItem('admin-notice', 'Build uploaded successfully'); } catch {}
        location.href = form.dataset.returnUrl;
      } catch (error) {
        state('Upload failed', error.message, 0);
        progress.append(button('Retry upload', () => form.requestSubmit()), button('Dismiss', () => progress.remove()));
      } finally { activeUpload = false; form.classList.remove('uploading'); controls.forEach((node, index) => node.disabled = disabled[index]); }
    });
  });
  try { const message = sessionStorage.getItem('admin-notice'); if (message) { sessionStorage.removeItem('admin-notice'); toast(message); } } catch {}
}

initAdmin();
