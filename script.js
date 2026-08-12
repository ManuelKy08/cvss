(function () {
  'use strict';

  /* ============================================================
     CVSS v3.1 metric weights (official FIRST.org specification)
     ============================================================ */
  const WEIGHTS = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR: {
      // Privileges Required depends on Scope
      U: { N: 0.85, L: 0.62, H: 0.27 },
      C: { N: 0.85, L: 0.68, H: 0.5 }
    },
    UI: { N: 0.85, R: 0.62 },
    CIA: { N: 0, L: 0.22, H: 0.56 } // shared by Confidentiality / Integrity / Availability
  };

  const SEVERITY_TIERS = [
    { name: 'None',     min: 0.0, max: 0.0,  className: 'sev-none' },
    { name: 'Low',      min: 0.1, max: 3.9,  className: 'sev-low' },
    { name: 'Medium',   min: 4.0, max: 6.9,  className: 'sev-medium' },
    { name: 'High',     min: 7.0, max: 8.9,  className: 'sev-high' },
    { name: 'Critical', min: 9.0, max: 10.0, className: 'sev-critical' }
  ];

  // indicative bounty payout bands, mapped within each severity tier
  const BOUNTY_BANDS = {
    None:     { lo: 0,    hi: 0 },
    Low:      { lo: 1,    hi: 150 },
    Medium:   { lo: 150,  hi: 1000 },
    High:     { lo: 1000, hi: 5000 },
    Critical: { lo: 5000, hi: 10000 }
  };

  const DEFAULT_STATE = { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' };
  const state = Object.assign({}, DEFAULT_STATE);

  /* ============================================================
     CVSS v3.1 base score equation
     ============================================================ */
  function roundUp(input) {
    // Official CVSS roundup: round to nearest 0.1, always upward.
    const intInput = Math.round(input * 100000);
    if (intInput % 10000 === 0) {
      return intInput / 100000;
    }
    return (Math.floor(intInput / 10000) + 1) / 10;
  }

  function computeScore(s) {
    const av = WEIGHTS.AV[s.AV];
    const ac = WEIGHTS.AC[s.AC];
    const pr = WEIGHTS.PR[s.S][s.PR];
    const ui = WEIGHTS.UI[s.UI];
    const c = WEIGHTS.CIA[s.C];
    const i = WEIGHTS.CIA[s.I];
    const a = WEIGHTS.CIA[s.A];

    const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
    let isc;
    if (s.S === 'U') {
      isc = 6.42 * iscBase;
    } else {
      isc = 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15);
    }

    const exploitability = 8.22 * av * ac * pr * ui;

    if (isc <= 0) return 0;

    let base;
    if (s.S === 'U') {
      base = roundUp(Math.min(isc + exploitability, 10));
    } else {
      base = roundUp(Math.min(1.08 * (isc + exploitability), 10));
    }
    return base;
  }

  function severityFor(score) {
    return SEVERITY_TIERS.find((t) => score >= t.min && score <= t.max) || SEVERITY_TIERS[0];
  }

  function bountyFor(score, severityName) {
    const band = BOUNTY_BANDS[severityName];
    if (band.lo === band.hi) return 0;
    const tier = SEVERITY_TIERS.find((t) => t.name === severityName);
    const pct = tier.max === tier.min ? 0 : (score - tier.min) / (tier.max - tier.min);
    const value = band.lo + pct * (band.hi - band.lo);
    return Math.round(value);
  }

  function vectorFor(s) {
    return `CVSS:3.1/AV:${s.AV}/AC:${s.AC}/PR:${s.PR}/UI:${s.UI}/S:${s.S}/C:${s.C}/I:${s.I}/A:${s.A}`;
  }

  /* ============================================================
     DOM wiring
     ============================================================ */
  const els = {
    scoreValue: document.getElementById('scoreValue'),
    severityLabel: document.getElementById('severityLabel'),
    scoreMarker: document.getElementById('scoreMarker'),
    vectorString: document.getElementById('vectorString'),
    bountyValue: document.getElementById('bountyValue'),
    bountyMarker: document.getElementById('bountyMarker'),
    metricHelp: document.getElementById('metricHelp'),
    copyBtn: document.getElementById('copyVector'),
    readout: document.querySelector('.readout')
  };

  function formatUSD(n) {
    if (n <= 0) return '$0';
    return '$' + n.toLocaleString('en-US');
  }

  function logPosition(value, min, max) {
    // position (0-100) on a log scale, used for the bounty bar marker
    if (value <= 0) return 0;
    const logMin = Math.log10(min);
    const logMax = Math.log10(max);
    const logVal = Math.log10(Math.max(value, min));
    return Math.min(100, Math.max(0, ((logVal - logMin) / (logMax - logMin)) * 100));
  }

  function render() {
    const score = computeScore(state);
    const severity = severityFor(score);
    const bounty = bountyFor(score, severity.name);
    const vector = vectorFor(state);

    els.scoreValue.textContent = score.toFixed(1);
    els.severityLabel.textContent = severity.name;
    els.vectorString.textContent = vector;
    els.bountyValue.textContent = formatUSD(bounty);

    els.scoreMarker.style.left = (score / 10) * 100 + '%';
    els.bountyMarker.style.left = logPosition(Math.max(bounty, 1), 1, 10000) + '%';

    SEVERITY_TIERS.forEach((t) => els.readout.classList.remove(t.className));
    els.readout.classList.add(severity.className);
  }

  function setActive(metricRow, key) {
    metricRow.querySelectorAll('button').forEach((btn) => {
      const pressed = btn.dataset.key === key;
      btn.setAttribute('aria-pressed', pressed ? 'true' : 'false');
    });
  }

  document.querySelectorAll('.metric-row').forEach((row) => {
    const metric = row.dataset.metric;
    const buttons = row.querySelectorAll('button');

    setActive(row, state[metric]);

    buttons.forEach((btn) => {
      btn.addEventListener('click', () => {
        state[metric] = btn.dataset.key;
        setActive(row, btn.dataset.key);
        render();
      });
      btn.addEventListener('mouseenter', () => {
        els.metricHelp.textContent = btn.dataset.help;
      });
      btn.addEventListener('focus', () => {
        els.metricHelp.textContent = btn.dataset.help;
      });
    });
  });

  els.copyBtn.addEventListener('click', () => {
    const text = els.vectorString.textContent;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(flashCopied, () => fallbackCopy(text));
    } else {
      fallbackCopy(text);
    }
  });

  function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) { /* no-op */ }
    document.body.removeChild(ta);
    flashCopied();
  }

  function flashCopied() {
    const original = els.copyBtn.textContent;
    els.copyBtn.textContent = 'Copied';
    els.copyBtn.classList.add('copied');
    setTimeout(() => {
      els.copyBtn.textContent = original;
      els.copyBtn.classList.remove('copied');
    }, 1400);
  }

  render();
})();
