(() => {
  const states = { Queued: '排队中', Enumerating: '遍历中', Hashing: '读取校验中', Completed: '已完成', PartialFailure: '部分失败', Cancelled: '已取消', Interrupted: '已中断', Failed: '失败' };
  const active = new Set(['Queued', 'Enumerating', 'Hashing']);
  const bytes = value => { let n = value, u = 0; const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']; while(n >= 1024 && u < units.length - 1){n /= 1024; u++;} return `${Number(n.toFixed(2))} ${units[u]}`; };
  for (const panel of document.querySelectorAll('[data-scan-id][data-live="true"]')) {
    let stopped = false;
    const poll = async () => {
      if (stopped) return;
      try {
        const response = await fetch(`/api/scans/${encodeURIComponent(panel.dataset.scanId)}`, { credentials: 'same-origin', cache: 'no-store' });
        if(response.status === 401){ stopped = true; panel.querySelector('[data-poll-status]').textContent = '会话已失效。刷新页面并重新登录。'; return; }
        if(!response.ok) throw new Error('poll');
        const data = await response.json(), scan = data.scan, progress = data.progress;
        const state = progress?.state ?? scan.state;
        panel.querySelector('[data-live-state]').textContent = states[state] ?? state;
        panel.querySelector('[data-live-files]').textContent = (progress?.files ?? scan.fileCount).toLocaleString();
        panel.querySelector('[data-live-bytes]').textContent = bytes(progress?.bytesRead ?? scan.bytesRead);
        panel.querySelector('[data-live-errors]').textContent = progress?.errors ?? scan.errorCount;
        if(!active.has(state)){ stopped = true; location.reload(); return; }
        panel.querySelector('[data-poll-status]').textContent = '扫描进行中，每 1.5 秒刷新进度。';
      } catch { panel.querySelector('[data-poll-status]').textContent = '暂时无法获取进度，正在重试。任务可能仍在服务端运行。'; }
      window.setTimeout(poll, 1500);
    };
    window.setTimeout(poll, 700);
  }
  for (const form of document.querySelectorAll('form[method="post"]')) {
    form.addEventListener('submit', event => {
      if (form.dataset.download === 'true') return;
      const button = event.submitter;
      if (button) { button.disabled = true; button.textContent = form.dataset.busyLabel || '正在处理…'; }
      form.setAttribute('aria-busy', 'true');
    });
  }
})();
