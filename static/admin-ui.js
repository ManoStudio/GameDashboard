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
  const updateThemeLabels = () => $$('[data-theme-toggle]').forEach(node => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    node.setAttribute('aria-label', 'Switch to ' + next + ' theme');
    node.title = 'Switch to ' + next + ' theme';
  });
  updateThemeLabels();
  const navToggle = $('[data-nav-toggle]');
  if (navToggle) {
    document.body.classList.add('navigation-ready');
    const setNavigation = open => {
      document.body.classList.toggle('nav-open', open);
      navToggle.setAttribute('aria-expanded', String(open));
      navToggle.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    };
    navToggle.addEventListener('click', () => setNavigation(!document.body.classList.contains('nav-open')));
    document.addEventListener('keydown', event => {
      if (event.key === 'Escape' && document.body.classList.contains('nav-open')) {
        setNavigation(false); navToggle.focus();
      }
    });
  }
  const revealFragment = () => {
    try {
      const id = decodeURIComponent(location.hash.slice(1));
      const node = id && document.getElementById(id);
      if (node?.tagName === 'DETAILS') node.open = true;
    } catch {}
  };
  window.addEventListener('hashchange', revealFragment);
  $$('a[href^="#"]').forEach(anchor => anchor.addEventListener('click', () => {
    const node = document.getElementById(anchor.getAttribute('href').slice(1));
    if (node?.tagName === 'DETAILS') node.open = true;
  }));
  revealFragment();
  $$('[data-theme-toggle]').forEach(node => node.addEventListener('click', () => {
    const theme = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('game-build-dashboard-theme', theme); } catch {}
    updateThemeLabels();
  }));
  $$('[data-project-selector]').forEach(node => node.addEventListener('change', () => {
    const url = new URL(location.href); url.searchParams.set('project', node.value);
    ['log_project', 'log_version', 'build', 'log', 'report'].forEach(key => url.searchParams.delete(key));
    if (url.searchParams.get('view') === 'report') url.searchParams.set('view', 'logs');
    if (['build', 'log'].includes(url.searchParams.get('view'))) url.searchParams.set('view', 'dashboard');
    location.href = url;
  }));
  $$('[data-copy]').forEach(node => node.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(node.dataset.copy); toast('Copied to clipboard'); }
    catch { toast('Unable to copy. Select the value and copy it manually.'); }
  }));
  $$('[data-discord-panel]').forEach(panel => {
    const form = $('[data-discord-settings]', panel);
    const input = $('input[name="webhook_url"]', form);
    const status = $('[data-discord-status]', panel);
    const badge = $('[data-discord-configured]', panel);
    const test = $('[data-discord-test]', panel);
    const remove = $('[data-discord-remove]', panel);
    const save = $('button[type="submit"]', form);
    let configured = !test.disabled;
    let busy = false;
    let dirty = false;
    function controls() {
      save.disabled = busy;
      test.disabled = busy || !configured || dirty;
      remove.disabled = busy || !configured;
      input.disabled = busy;
      $$('input[type="checkbox"]', form).forEach(node => node.disabled = busy);
    }
    function apply(settings) {
      configured = settings.configured;
      input.value = '';
      input.placeholder = configured ? 'Leave blank to keep the saved webhook' : 'https://discord.com/api/webhooks/…';
      $('input[name="enabled"]', form).checked = settings.enabled;
      $$('input[name="channels"]', form).forEach(node => node.checked = settings.channels.includes(node.value));
      badge.textContent = configured ? 'Webhook saved' : 'Not configured';
      dirty = false;
    }
    async function call(method, suffix = '', payload) {
      const response = await fetch(panel.dataset.discordEndpoint + suffix, {
        method, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'Content-Type': 'application/json' },
        ...(payload ? { body: JSON.stringify(payload) } : {}),
      });
      let data;
      try { data = await response.json(); }
      catch { throw new Error('Unable to load Discord settings. Check the Dashboard connection.'); }
      if (!response.ok) throw new Error(data.error || 'Unable to manage Discord notifications.');
      return data;
    }
    form.addEventListener('input', () => { dirty = true; controls(); });
    form.addEventListener('change', () => { dirty = true; controls(); });
    window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
    window.addEventListener('pagehide', () => { input.value = ''; });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (busy) return;
      const data = new FormData(form);
      const payload = { webhook_url: input.value, enabled: data.has('enabled'), channels: data.getAll('channels') };
      if (!payload.channels.length) { status.textContent = 'Select at least one upload channel.'; return; }
      busy = true; controls(); status.textContent = 'Saving notifications…';
      try {
        apply(await call('PUT', '', payload));
        status.textContent = 'Discord notification settings saved.';
      } catch (error) { status.textContent = error.message; }
      finally { busy = false; controls(); }
    });
    test.addEventListener('click', async () => {
      if (busy || dirty) return;
      busy = true; controls(); status.textContent = 'Sending a test message to Discord…';
      try { await call('POST', '/test'); status.textContent = 'Test message sent to your Discord channel.'; }
      catch (error) { status.textContent = error.message; }
      finally { busy = false; controls(); }
    });
    remove.addEventListener('click', async () => {
      if (busy || !confirm('Remove this project’s saved Discord webhook and stop notifications?')) return;
      busy = true; controls();
      try { apply(await call('DELETE')); status.textContent = 'Discord webhook removed.'; }
      catch (error) { status.textContent = error.message; }
      finally { busy = false; controls(); }
    });
  });
  $$('[data-token-panel]').forEach(panel => {
    const form = $('[data-token-create]', panel);
    const status = $('[data-token-status]', panel);
    const result = $('[data-token-result]', panel);
    const value = $('[data-token-value]', panel);
    const list = $('[data-token-list]', panel);
    const create = $('button[type="submit"]', form);
    let pendingSecret = false;
    let busy = false;
    const updateControls = () => {
      create.disabled = busy || pendingSecret;
      $$('[data-token-revoke]', panel).forEach(node => node.disabled = busy);
    };
    async function call(method, suffix = '', payload) {
      const response = await fetch(panel.dataset.tokenEndpoint + suffix, {
        method, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        headers: { 'Content-Type': 'application/json' },
        ...(payload ? { body: JSON.stringify(payload) } : {}),
      });
      let data;
      try { data = await response.json(); }
      catch { throw new Error('Unable to load API tokens. Check the Dashboard connection.'); }
      if (!response.ok) throw new Error(data.error || 'Unable to manage API tokens.');
      return data;
    }
    function render(tokens) {
      list.replaceChildren();
      if (!tokens.length) {
        const row = document.createElement('tr'); const cell = document.createElement('td');
        cell.colSpan = 6; cell.textContent = 'No API tokens for this project yet.'; row.append(cell); list.append(row); return;
      }
      tokens.forEach(token => {
        const row = document.createElement('tr');
        const state = token.revoked_at ? 'Revoked' : token.expires_at && Date.parse(token.expires_at) <= Date.now() ? 'Expired' : 'Active';
        const values = [token.name + ' (' + token.token_prefix + '…)', token.channels.join(', '), state, token.expires_at?.slice(0, 10) || 'Never', token.last_used_at?.replace('T', ' ').slice(0, 19) || 'Not used'];
        values.forEach(text => { const cell = document.createElement('td'); cell.textContent = text; row.append(cell); });
        const action = document.createElement('td');
        if (!token.revoked_at) {
          const revoke = button('Revoke', () => {}, 'btn secondary small danger-text');
          revoke.dataset.tokenRevoke = token.id; action.append(revoke);
        } else action.textContent = '—';
        row.append(action); list.append(row);
      });
    }
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (busy || pendingSecret) return;
      const data = new FormData(form);
      const channels = data.getAll('channels');
      if (!channels.length) { status.textContent = 'Select at least one upload channel.'; return; }
      busy = true; updateControls(); status.textContent = 'Creating token…';
      try {
        const issued = await call('POST', '', { name: data.get('name'), channels, expires_in_days: Number(data.get('expires_in_days')) });
        value.value = issued.token; result.hidden = false; pendingSecret = true;
        form.reset(); value.focus(); value.select();
        status.textContent = 'Token created. Save it in GitHub Secrets before closing this page.';
        try { render(await call('GET')); }
        catch { status.textContent += ' The list could not refresh; your new token is shown above.'; }
      } catch (error) { status.textContent = error.message; }
      finally { busy = false; updateControls(); }
    });
    panel.addEventListener('click', async event => {
      const revoke = event.target.closest('[data-token-revoke]');
      if (!revoke || busy || !confirm('Revoke this token? Workflows using it will no longer authenticate.')) return;
      busy = true; updateControls();
      try {
        await call('DELETE', '/' + encodeURIComponent(revoke.dataset.tokenRevoke));
        status.textContent = 'Token revoked.';
        render(await call('GET'));
      } catch (error) { status.textContent = error.message; }
      finally { busy = false; updateControls(); }
    });
    $('[data-token-copy]', panel).addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(value.value); toast('Token copied. Paste it into GitHub Secrets.'); }
      catch { value.focus(); value.select(); toast('Select the token and copy it manually.'); }
    });
    $('[data-token-done]', panel).addEventListener('click', () => {
      value.value = ''; result.hidden = true; pendingSecret = false; updateControls();
      status.textContent = 'Token saved. You can create another token or revoke an existing one.';
    });
    window.addEventListener('beforeunload', event => { if (pendingSecret) { event.preventDefault(); event.returnValue = ''; } });
    // Clear the one-time secret before this document enters the back/forward cache.
    window.addEventListener('pagehide', () => { value.value = ''; result.hidden = true; pendingSecret = false; });
  });
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
    const versionOrder = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });
    const recent = table.hasAttribute('data-recent'); const pageSize = recent ? 6 : 20; let page = 0;
    const reset = button('Clear filters', () => {
      search.value = ''; channel.value = ''; status.value = ''; sort.value = 'date-desc'; page = 0; renderBuildResults(); search.focus();
    });
    reset.classList.add('filter-reset'); summary.append(reset);
    const summaryText = document.createElement('span'); summary.prepend(summaryText);
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
      const visible = matching.slice(page * pageSize, (page + 1) * pageSize);
      body.replaceChildren(...visible.map(item => item.row));
      if (!matching.length) { const row = body.insertRow(); const cell = row.insertCell(); cell.colSpan = table.tHead.rows[0].cells.length; cell.className = 'empty'; cell.textContent = 'No builds match these filters. Try another search.'; }
      summaryText.textContent = active ? matching.length + ' matching builds' : recent ? 'Showing ' + Math.min(matching.length, pageSize) + (matching.length > pageSize ? ' most recent of ' : ' of ') + matching.length + ' builds' : matching.length + ' builds';
      reset.hidden = !active;
      count.textContent = matching.length + ' results · Page ' + (page + 1) + ' of ' + pages; pager.hidden = (recent && !active) || pages <= 1;
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
      const select = document.createElement('select'); select.setAttribute('aria-label', 'Filter ' + key); select.add(new Option('All ' + ({ channel: 'channels', platform: 'platforms', status: 'statuses' }[key] || key), ''));
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
    if (source.hasAttribute('data-plain-notes')) return;
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

  $$('form[data-build-details]').forEach(form => {
    const status = $('[data-details-status]', form);
    const save = $('button[type="submit"]', form);
    let dirty = false;
    let saving = false;
    form.addEventListener('input', () => { dirty = true; });
    window.addEventListener('beforeunload', event => { if (dirty) { event.preventDefault(); event.returnValue = ''; } });
    form.addEventListener('submit', async event => {
      event.preventDefault();
      if (saving) return;
      const payload = Object.fromEntries(new FormData(form));
      saving = true; save.disabled = true; status.textContent = 'Saving build details…';
      try {
        const response = await fetch(form.dataset.detailsUrl, {
          method: 'PATCH', credentials: 'same-origin', redirect: 'error',
          headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload),
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Unable to save build details.');
        dirty = false; status.textContent = 'Details saved.';
        location.hash = 'edit-build-details'; location.reload();
      } catch (error) { status.textContent = error.message; }
      finally { saving = false; save.disabled = false; }
    });
  });

  $$('[data-upload-queue]').forEach(panel => {
    const endpoint = panel.dataset.uploadQueue;
    let jobs = [], saving = false, fetching = false, dragging = '', fingerprint = '';
    const status = $('[data-queue-status]', panel);
    const size = bytes => bytes >= 1073741824 ? (bytes / 1073741824).toFixed(2) + ' GB' : bytes >= 1048576 ? (bytes / 1048576).toFixed(1) + ' MB' : (bytes / 1024).toFixed(1) + ' KB';
    const node = (tag, text, className = '') => { const element = document.createElement(tag); element.textContent = text; element.className = className; return element; };
    async function request(path, options = {}) {
      const response = await fetch(path, { ...options, cache: 'no-store', signal: AbortSignal.timeout(15000) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Could not load the upload queue.');
      return data;
    }
    function draw(data) {
      jobs = data.jobs;
      const active = jobs.filter(job => job.status !== 'waiting'), waiting = jobs.filter(job => job.status === 'waiting');
      $('[data-queue-active-count]', panel).textContent = active.length;
      $('[data-queue-waiting-count]', panel).textContent = waiting.length;
      $('[data-queue-refresh]', panel).textContent = 'Live · refreshes every 3 seconds';
      const nextFingerprint = JSON.stringify(jobs);
      if (nextFingerprint === fingerprint) return;
      fingerprint = nextFingerprint;
      const focused = document.activeElement?.closest('[data-queue-id]')?.dataset.queueId;
      const direction = document.activeElement?.dataset.direction;
      for (const [selector, items, emptyTitle, emptyText] of [
        ['[data-queue-active]', active, 'No uploads in progress', 'Incoming builds will appear here when they start uploading.'],
        ['[data-queue-waiting]', waiting, 'The queue is clear', 'Builds arriving together will wait here in upload order.'],
      ]) {
        const list = $(selector, panel); list.replaceChildren();
        if (!items.length) { const empty = node('div', '', 'queue-empty'); empty.append(node('strong', emptyTitle), node('span', emptyText)); list.append(empty); }
        items.forEach((job, index) => {
          const row = node('article', '', 'queue-item'); row.dataset.queueId = job.build_id; row.dataset.waiting = String(job.status === 'waiting');
          const handle = node('span', job.position || '↑', 'queue-position'); row.append(handle);
          const description = node('div', '', 'queue-description');
          description.append(node('strong', job.version), node('p', job.files.join(', ') || 'Package metadata unavailable'), node('p', [job.source || 'Dashboard', job.branch].filter(Boolean).join(' · ')), node('span', job.channel.toUpperCase(), 'channel-tag'));
          row.append(description);
          const transfer = node('div', '', 'queue-transfer');
          const label = job.status === 'waiting' ? 'Waiting for upload slot' : job.status === 'legacy' ? 'Uploading · legacy script' : ({ preparing: 'Preparing upload', hashing: 'Computing checksum', uploading: 'Uploading', finalizing: 'Saving build metadata' }[job.phase] || 'Uploading');
          transfer.append(node('strong', label));
          if (job.status !== 'waiting' && job.status !== 'legacy') {
            const percent = job.total_bytes ? Math.min(100, Math.round(job.uploaded_bytes / job.total_bytes * 100)) : 0;
            const bar = document.createElement('progress'); bar.max = 100; bar.value = percent; bar.setAttribute('aria-label', job.version + ' upload progress'); transfer.append(bar);
            transfer.append(node('span', percent + '% · ' + size(job.uploaded_bytes) + ' / ' + size(job.total_bytes)));
          } else transfer.append(node('span', job.status === 'legacy' ? 'Update the CI uploader to use queue ordering.' : size(job.total_bytes) + ' · next #' + job.position));
          row.append(transfer);
          const controls = node('div', '', 'queue-controls');
          if (job.status === 'waiting') {
            handle.title = 'Drag to reorder'; handle.style.touchAction = 'none';
            let dragTarget = -1, pointerStart, moved = false;
            handle.addEventListener('pointerdown', event => {
              if (saving || fetching || event.button !== 0) return;
              event.preventDefault(); dragging = job.build_id; pointerStart = [event.clientX, event.clientY]; moved = false; dragTarget = -1; handle.setPointerCapture(event.pointerId);
            });
            handle.addEventListener('pointermove', event => {
              if (dragging !== job.build_id || !pointerStart) return;
              if (Math.hypot(event.clientX - pointerStart[0], event.clientY - pointerStart[1]) < 6 && !moved) return;
              moved = true; row.classList.add('dragging');
              const target = document.elementFromPoint(event.clientX, event.clientY)?.closest('[data-waiting="true"]');
              $$('.drop-target', panel).forEach(item => item.classList.remove('drop-target'));
              dragTarget = target ? waiting.findIndex(item => item.build_id === target.dataset.queueId) : -1;
              if (dragTarget !== -1 && target !== row) target.classList.add('drop-target');
            });
            const endPointerDrag = event => {
              if (dragging !== job.build_id || !pointerStart) return;
              const target = dragTarget; dragging = ''; pointerStart = undefined; row.classList.remove('dragging'); $$('.drop-target', panel).forEach(item => item.classList.remove('drop-target'));
              if (handle.hasPointerCapture(event.pointerId)) handle.releasePointerCapture(event.pointerId);
              if (event.type === 'pointerup' && moved && target >= 0 && target !== index) moveJob(job.build_id, target);
            };
            handle.addEventListener('pointerup', endPointerDrag); handle.addEventListener('pointercancel', endPointerDrag);
            for (const [delta, label, glyph] of [[-1, 'Move up', '↑'], [1, 'Move down', '↓']]) {
              const move = button(glyph, () => moveJob(job.build_id, index + delta)); move.setAttribute('aria-label', label + ' ' + job.version); move.title = label; move.dataset.direction = String(delta); move.disabled = index + delta < 0 || index + delta >= items.length; controls.append(move);
            }
            row.draggable = true;
            row.addEventListener('dragstart', event => { if (saving) { event.preventDefault(); return; } dragging = job.build_id; event.dataTransfer.setData('text/plain', job.build_id); event.dataTransfer.effectAllowed = 'move'; row.classList.add('dragging'); });
            row.addEventListener('dragover', event => { if (dragging && dragging !== job.build_id) { event.preventDefault(); row.classList.add('drop-target'); } });
            row.addEventListener('dragleave', () => row.classList.remove('drop-target'));
            row.addEventListener('drop', event => { event.preventDefault(); row.classList.remove('drop-target'); const id = dragging; dragging = ''; if (id && id !== job.build_id) moveJob(id, index); });
            row.addEventListener('dragend', () => { dragging = ''; row.classList.remove('dragging'); $$('.drop-target', panel).forEach(item => item.classList.remove('drop-target')); });
          }
          row.append(controls); list.append(row);
        });
      }
      if (focused && direction) $$('[data-queue-id]', panel).find(row => row.dataset.queueId === focused)?.querySelector('[data-direction="' + direction + '"]')?.focus();
    }
    async function refresh() {
      if (saving || fetching || dragging || document.hidden) return;
      fetching = true;
      try { draw(await request(endpoint)); }
      catch (error) { status.textContent = error.message; $('[data-queue-refresh]', panel).textContent = 'Connection interrupted · retrying'; }
      finally { fetching = false; }
    }
    async function moveJob(id, target) {
      if (saving || fetching) return;
      const ids = jobs.filter(job => job.status === 'waiting').map(job => job.build_id); const from = ids.indexOf(id);
      if (from < 0 || target < 0 || target >= ids.length) return;
      ids.splice(from, 1); ids.splice(target, 0, id); saving = true;
      $$('[data-direction]', panel).forEach(control => control.disabled = true);
      try { draw(await request(endpoint + '/reorder', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ build_ids: ids }) })); status.textContent = 'Upload order saved.'; }
      catch (error) { status.textContent = error.message; fingerprint = ''; }
      finally { saving = false; fingerprint = ''; await refresh(); }
    }
    $('[data-queue-reload]', panel).addEventListener('click', refresh);
    const timer = setInterval(refresh, 3000); window.addEventListener('pagehide', () => clearInterval(timer), { once: true }); refresh();
  });

  let activeUpload = false;
  window.addEventListener('beforeunload', event => { if (activeUpload) { event.preventDefault(); event.returnValue = ''; } });
  $$('form[data-direct-upload]').forEach(form => {
    const input = $('input[type=file]', form); const zone = input.closest('.dropzone');
    const layout = form.closest('.upload-layout');
    const channelHints = {
      dev: 'Development builds are available to developers and admins.',
      qa: 'QA builds are available to QA, developers, and admins.',
      live: 'Live builds are available to viewer accounts and the rest of your team.',
      deprecated: 'Deprecated builds are retained outside the active release channels.',
      stable: 'Stable builds are available in the stable release channel.',
    };
    const updateReleaseSummary = () => {
      if (!layout) return;
      const files = Array.from(input.files);
      const channel = $('select[name=channel]', form);
      const values = {
        '[data-summary-package]': files.length ? files.length + (files.length === 1 ? ' file selected' : ' files selected') : 'No files selected',
        '[data-summary-size]': files.length ? format(files.reduce((sum, file) => sum + file.size, 0)) : '—',
        '[data-summary-channel]': channel?.selectedOptions[0]?.textContent || 'Not selected',
        '[data-summary-tag]': $('input[name=tag]', form)?.value.trim() || 'None',
      };
      Object.entries(values).forEach(([selector, value]) => {
        const node = $(selector, layout); if (node) node.textContent = value;
      });
      const hint = $('[data-channel-hint]', form); if (hint) hint.textContent = channelHints[channel?.value] || '';
    };
    const summary = document.createElement('p'); summary.className = 'file-summary'; summary.setAttribute('aria-live', 'polite'); zone.after(summary);
    const format = bytes => bytes >= 1073741824 ? (bytes / 1073741824).toFixed(2) + ' GB' : (bytes / 1048576).toFixed(1) + ' MB';
    const selected = () => { const files = Array.from(input.files); summary.textContent = files.length ? files.map(file => file.name).join(', ') + ' · ' + format(files.reduce((sum, file) => sum + file.size, 0)) : ''; updateReleaseSummary(); };
    form.addEventListener('input', updateReleaseSummary);
    form.addEventListener('change', updateReleaseSummary);
    updateReleaseSummary();
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
      const queueLink = document.createElement('a'); queueLink.textContent = 'Open upload queue ↗'; queueLink.href = form.dataset.returnUrl.replace('view=builds', 'view=queue'); queueLink.target = '_blank'; queueLink.rel = 'noopener'; progress.append(queueLink);
      let session, heartbeat, reporting, uploadedBytes = 0, phase = 'preparing', heartbeatError, currentXhr, cancelled = false, confirmed = false;
      const cancel = button('Cancel upload', () => { cancelled = true; currentXhr?.abort(); }); progress.append(cancel);
      const check = () => { if (cancelled) throw new Error('Upload cancelled.'); if (heartbeatError) throw heartbeatError; };
      const reportProgress = async () => {
        if (reporting) return reporting;
        reporting = (async () => {
          const response = await fetch(form.dataset.completeBase + '/' + session.build_id + '/progress', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ uploaded_bytes: uploadedBytes, phase }), signal: AbortSignal.timeout(15000) });
          if (!response.ok) throw new Error('Could not report upload progress.');
          const job = await response.json();
          if (job.status !== 'uploading') throw new Error('The upload session expired. Please retry.');
        })().finally(() => { reporting = undefined; });
        return reporting;
      };
      try {
        state('Preparing upload', 'Requesting an upload session…');
        const init = await fetch(form.dataset.initUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...data, queue: true, files: files.map(file => ({ name: file.name, size: file.size, content_type: file.type || 'application/octet-stream' })) }), signal: AbortSignal.timeout(30000) });
        if (init.status === 503 && form.dataset.demo === 'true') { activeUpload = false; controls.forEach((node, index) => node.disabled = disabled[index]); HTMLFormElement.prototype.submit.call(form); return; }
        if (!init.ok) throw new Error('Could not prepare the upload. Check your connection, access, and storage configuration.');
        session = await init.json();
        while (session.status === 'waiting') {
          check(); state('Waiting in upload queue', session.version + ' · position #' + session.position + '. Keep this tab open.');
          await new Promise(resolve => setTimeout(resolve, 3000)); check();
          const response = await fetch(form.dataset.completeBase + '/' + session.build_id + '/status', { cache: 'no-store', signal: AbortSignal.timeout(15000) });
          if (!response.ok) throw new Error('Could not check the upload queue.'); session = await response.json();
        }
        check();
        if (session.status && session.status !== 'uploading') throw new Error('The upload session expired. Please retry.');
        heartbeat = setInterval(() => reportProgress().catch(error => { heartbeatError = error; currentXhr?.abort(); }), 10000);
        const uploaded = []; const total = files.reduce((sum, file) => sum + file.size, 0); let sent = 0; let started = 0;
        for (let index = 0; index < files.length; index++) {
          const file = files[index]; const target = session.uploads[index];
          check(); phase = 'hashing'; await reportProgress();
          state('Validating package', 'Computing checksum for ' + file.name);
          const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
          const hash = Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, '0')).join('');
          check(); phase = 'uploading'; await reportProgress();
          started = performance.now();
          await new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest(); currentXhr = xhr; xhr.open('PUT', target.upload_url); xhr.setRequestHeader('Content-Type', target.content_type);
            xhr.upload.onprogress = event => { const loaded = Math.min(event.loaded, file.size); uploadedBytes = sent + loaded; const speed = loaded / Math.max((performance.now() - started) / 1000, .1); state('Uploading build', `${format(sent + loaded)} / ${format(total)} · ${format(speed)}/s`, total ? (sent + loaded) / total * 100 : 0); };
            xhr.onload = () => xhr.status >= 200 && xhr.status < 300 ? resolve() : reject(new Error('The package could not be uploaded. Check storage access and retry.'));
            xhr.onabort = () => reject(heartbeatError || new Error('Upload cancelled.')); xhr.onerror = () => reject(new Error('Connection interrupted. Check your connection and retry.')); xhr.timeout = 25 * 60 * 1000; xhr.ontimeout = () => reject(new Error('Upload timed out. Please retry.')); xhr.send(file);
          });
          sent += file.size; uploaded.push({ name: file.name, size: file.size, hash, content_type: target.content_type, object_path: target.object_path });
          uploadedBytes = sent; currentXhr = undefined;
        }
        state('Processing build', 'Saving manifest and build metadata…');
        check(); phase = 'finalizing'; await reportProgress(); clearInterval(heartbeat); cancel.disabled = true;
        const complete = await fetch(form.dataset.completeBase + '/' + session.build_id + '/complete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...data, version: session.version, files: uploaded }) });
        if (!complete.ok) throw new Error('The server could not confirm this build. Check build history before retrying.');
        confirmed = true;
        state('Build ready', 'Upload completed successfully.', 100); activeUpload = false;
        try { sessionStorage.setItem('admin-notice', 'Build uploaded successfully'); } catch {}
        location.href = form.dataset.returnUrl;
      } catch (error) {
        clearInterval(heartbeat); if (reporting) await reporting.catch(() => {});
        if (session?.build_id && !confirmed) await fetch(form.dataset.completeBase + '/' + session.build_id + '/fail', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', signal: AbortSignal.timeout(10000) }).catch(() => {});
        cancel.remove();
        state('Upload failed', error.message, 0);
        progress.append(button('Retry upload', () => form.requestSubmit()), button('Dismiss', () => progress.remove()));
      } finally { clearInterval(heartbeat); activeUpload = false; form.classList.remove('uploading'); controls.forEach((node, index) => node.disabled = disabled[index]); }
    });
  });
  try { const message = sessionStorage.getItem('admin-notice'); if (message) { sessionStorage.removeItem('admin-notice'); toast(message); } } catch {}
}

function parseUnityLog(text) {
  const entries = [];
  const header = /^(?:(\d{4}-\d{2}-\d{2}T\S+)\s+)?\[(Log|Warning|Error|Exception|Assert)\]\s?(.*)$/i;
  for (const line of text.replace(/\r\n?/g, '\n').split('\n')) {
    const match = header.exec(line);
    if (match) {
      const type = match[2].toLowerCase();
      entries.push({ id: entries.length, time: match[1] || '', level: type === 'warning' ? 'warning' : ['error', 'exception', 'assert'].includes(type) ? 'error' : 'log', message: match[3], raw: line });
    } else if (entries.length) {
      entries[entries.length - 1].raw += '\n' + line;
    } else if (line.trim()) {
      entries.push({ id: entries.length, time: '', level: 'log', message: line, raw: line });
    }
  }
  return entries;
}

function initReportConsole() {
  const root = document.querySelector('[data-report-console]');
  if (!root) return;
  const $ = selector => root.querySelector(selector);
  const list = $('[data-log-list]'), state = $('[data-console-state]'), detail = $('[data-log-detail]');
  let entries = [], filtered = [], page = 0, level = 'all', selected = null, loading = false;
  const pageSize = 100;
  function render() {
    const search = $('[data-log-search]').value.toLowerCase();
    const counts = { all: entries.length, log: 0, warning: 0, error: 0 };
    entries.forEach(entry => counts[entry.level]++);
    root.querySelectorAll('[data-log-count]').forEach(node => node.textContent = counts[node.dataset.logCount]);
    filtered = entries.filter(entry => (level === 'all' || entry.level === level) && entry.raw.toLowerCase().includes(search));
    if ($('[data-log-collapse]').checked) {
      const groups = new Map();
      filtered.forEach(entry => {
        const key = entry.level + '\n' + entry.raw.replace(/^\d{4}-\d{2}-\d{2}T\S+\s+/, '');
        const existing = groups.get(key);
        if (existing) existing.count++;
        else groups.set(key, { ...entry, count: 1 });
      });
      filtered = [...groups.values()];
    }
    page = Math.max(0, Math.min(page, Math.ceil(filtered.length / pageSize) - 1));
    const visible = filtered.slice(page * pageSize, (page + 1) * pageSize);
    if (selected !== null && !filtered.some(entry => entry.id === selected)) {
      selected = null; detail.textContent = 'Select a log entry to inspect its full message and stack trace.'; $('[data-copy-entry]').disabled = true;
    }
    list.replaceChildren();
    visible.forEach(entry => {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'console-entry'; button.setAttribute('aria-pressed', String(entry.id === selected));
      for (const [className, text] of [['entry-level ' + entry.level, entry.level.toUpperCase()], ['entry-time', entry.time ? entry.time.slice(11, 23) : '—'], ['entry-message', entry.message], ['entry-count', entry.count > 1 ? '×' + entry.count : '']]) {
        const span = document.createElement('span'); span.className = className; span.textContent = text; button.append(span);
      }
      button.addEventListener('click', () => { selected = entry.id; detail.textContent = entry.raw;  $('[data-copy-entry]').disabled = false; list.querySelectorAll('.console-entry').forEach(node => node.setAttribute('aria-pressed', String(node === button))); });
      list.append(button);
    });
    $('[data-log-page]').textContent = filtered.length ? `${page * pageSize + 1}–${Math.min((page + 1) * pageSize, filtered.length)} of ${filtered.length} entries` : '0 entries';
    $('[data-log-prev]').disabled = page === 0;
    $('[data-log-next]').disabled = (page + 1) * pageSize >= filtered.length;
    if (!loading) { state.hidden = filtered.length > 0; state.textContent = entries.length ? 'No entries match these filters.' : root.dataset.logUrl ? 'The attached log is empty.' : 'No log attached to this report.'; }
  }
  async function load() {
    if (loading || !root.dataset.logUrl) return;
    loading = true; state.hidden = false; state.textContent = 'Loading logs…'; $('[data-log-retry]').disabled = true;
    try {
      const response = await fetch(root.dataset.logUrl, { credentials: 'same-origin', cache: 'no-store' });
      if (!response.ok) throw new Error(response.status === 401 ? 'Session expired. Sign in again to view logs.' : 'Unable to load log. Use Reload to try again.');
      entries = parseUnityLog(await response.text()); page = 0; selected = null;
      detail.textContent = 'Select a log entry to inspect its full message and stack trace.'; $('[data-copy-entry]').disabled = true;
      loading = false; render();
    } catch (error) { state.hidden = false; state.textContent = error.message; }
    finally { loading = false; $('[data-log-retry]').disabled = false; }
  }
  $('[data-log-search]').addEventListener('input', () => { page = 0; render(); });
  $('[data-log-collapse]').addEventListener('change', () => { page = 0; render(); });
  root.querySelectorAll('[data-log-level]').forEach(button => button.addEventListener('click', () => {
    level = button.dataset.logLevel; page = 0;
    root.querySelectorAll('[data-log-level]').forEach(node => node.setAttribute('aria-pressed', String(node === button))); render();
  }));
  $('[data-log-prev]').addEventListener('click', () => { page--; render(); list.scrollTop = 0; });
  $('[data-log-next]').addEventListener('click', () => { page++; render(); list.scrollTop = 0; });
  $('[data-log-retry]').addEventListener('click', load);
  $('[data-copy-entry]').addEventListener('click', async () => {
    const button = $('[data-copy-entry]');
    try { await navigator.clipboard.writeText(detail.textContent); button.textContent = 'Copied'; }
    catch { button.textContent = 'Copy failed — select text'; }
    setTimeout(() => button.textContent = 'Copy entry', 2000);
  });
  render(); void load();
}

initAdmin();
initReportConsole();
