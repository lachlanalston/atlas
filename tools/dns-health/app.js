// ─────────────────────────────────────────────────────────────
//  ATLAS — DNS Health  |  app.js
//  All checks run via Cloudflare DoH. Domain names only — no
//  client data leaves the browser.
// ─────────────────────────────────────────────────────────────

const DOH = 'https://cloudflare-dns.com/dns-query';

function validateDomain(domain) {
    if (!domain) return 'Enter a domain name.';
    // Must have at least one dot, valid characters, no consecutive dots, valid TLD
    if (/\.\./.test(domain))                                   return 'Invalid domain — consecutive dots detected.';
    if (domain.startsWith('.') || domain.endsWith('.'))        return 'Invalid domain — cannot start or end with a dot.';
    if (!/^[a-zA-Z0-9._-]+$/.test(domain))                    return 'Invalid domain — only letters, numbers, hyphens and dots allowed.';
    if (!/^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/.test(domain)) return 'Invalid domain — enter a full domain like example.com.';
    return null;
}

const DNSBL_ZONES = [
    { zone: 'zen.spamhaus.org',          label: 'Spamhaus ZEN'       },
    { zone: 'b.barracudacentral.org',    label: 'Barracuda'          },
    { zone: 'bl.spamcop.net',            label: 'SpamCop'            },
    { zone: 'dnsbl.sorbs.net',           label: 'SORBS'              },
    { zone: 'psbl.surriel.com',          label: 'PSBL'               },
    { zone: 'dnsbl.spfbl.net',           label: 'SPFBL'              },
    { zone: 'dnsbl-1.uceprotect.net',    label: 'UCEPROTECT L1'      },
    { zone: 'cbl.abuseat.org',           label: 'Abuseat CBL'        },
];

const DKIM_SELECTORS = [
    'google', 'selector1', 'selector2', 'default', 'k1',
    'mail', 'dkim', 's1', 's2', 'email',
];

// ─────────────────────────────────────────────────────────────
//  DOH HELPERS
// ─────────────────────────────────────────────────────────────

async function dohLookup(name, type) {
    try {
        const url = `${DOH}?name=${encodeURIComponent(name)}&type=${type}`;
        const res = await fetch(url, { headers: { Accept: 'application/dns-json' } });
        if (!res.ok) return null;
        return await res.json();
    } catch {
        return null;
    }
}

async function getTXT(name) {
    const data = await dohLookup(name, 'TXT');
    if (!data?.Answer) return [];
    return data.Answer
        .filter(r => r.type === 16)
        .map(r => r.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));
}

async function getMX(name) {
    const data = await dohLookup(name, 'MX');
    if (!data?.Answer) return [];
    return data.Answer
        .filter(r => r.type === 15)
        .map(r => {
            const parts = r.data.trim().split(/\s+/);
            return { priority: parseInt(parts[0], 10), host: parts[1]?.replace(/\.$/, '') || '' };
        })
        .sort((a, b) => a.priority - b.priority);
}

async function getA(name) {
    const data = await dohLookup(name, 'A');
    if (!data?.Answer) return [];
    return data.Answer.filter(r => r.type === 1).map(r => r.data);
}

async function getPTR(ip) {
    const reversed = ip.split('.').reverse().join('.');
    const data = await dohLookup(`${reversed}.in-addr.arpa`, 'PTR');
    if (!data?.Answer) return null;
    const rec = data.Answer.find(r => r.type === 12);
    return rec ? rec.data.replace(/\.$/, '') : null;
}

// ─────────────────────────────────────────────────────────────
//  SPF
// ─────────────────────────────────────────────────────────────

function parseSPF(record) {
    if (!record) return null;
    const mechanisms = record.split(/\s+/);
    const lookupMechanisms = mechanisms.filter(m =>
        /^[+~?-]?(include|a|mx|ptr|exists):/i.test(m) ||
        /^[+~?-]?(a|mx)$/i.test(m)
    );
    const all = mechanisms.find(m => /^[+~?-]?all$/i.test(m)) || '';
    const allQualifier = all.match(/^([+~?-])/)?.[1] || '+';

    return {
        record,
        lookupCount: lookupMechanisms.length,
        allQualifier,
        allLabel: { '+': 'Pass (+all)', '-': 'Fail (-all)', '~': 'SoftFail (~all)', '?': 'Neutral (?all)' }[allQualifier] || 'Unknown',
        mechanisms,
    };
}

function assessSPF(spf) {
    if (!spf) return { status: 'missing', severity: 'crit', label: 'No SPF record', detail: 'No SPF record found. Anyone can send email claiming to be from this domain.' };
    if (spf.allQualifier === '+') return { status: 'fail',    severity: 'crit',   label: 'SPF allows all senders (+all)', detail: 'The +all mechanism means any server can send as this domain. This is a critical misconfiguration.' };
    if (spf.lookupCount > 10)    return { status: 'warn',    severity: 'warn',   label: `SPF lookup limit exceeded (${spf.lookupCount}/10)`, detail: 'SPF allows a maximum of 10 DNS lookups. Exceeding this causes PermError and deliverability failures.' };
    if (spf.lookupCount > 8)     return { status: 'warn',    severity: 'warn',   label: `SPF near lookup limit (${spf.lookupCount}/10)`, detail: 'Approaching the 10-lookup limit. Adding more include: mechanisms may cause PermError.' };
    if (spf.allQualifier === '~') return { status: 'warn',    severity: 'warn',   label: 'SPF policy is SoftFail (~all)', detail: 'Unauthorised senders are marked but not rejected. Consider upgrading to -all for strict enforcement.' };
    if (spf.allQualifier === '?') return { status: 'warn',    severity: 'warn',   label: 'SPF policy is Neutral (?all)', detail: 'SPF provides no guidance on handling unauthorised senders. Effectively unenforced.' };
    return { status: 'pass', severity: 'pass', label: 'SPF configured (-all)', detail: 'SPF is present with strict enforcement. Unauthorised senders will be rejected.' };
}

// ─────────────────────────────────────────────────────────────
//  DMARC
// ─────────────────────────────────────────────────────────────

function parseDMARC(record) {
    if (!record) return null;
    const tags = {};
    record.split(';').forEach(part => {
        const [k, v] = part.trim().split('=');
        if (k && v !== undefined) tags[k.trim()] = v.trim();
    });
    return {
        record,
        policy:    tags.p    || 'none',
        spolicy:   tags.sp   || tags.p || 'none',
        pct:       tags.pct  ? parseInt(tags.pct, 10) : 100,
        rua:       tags.rua  || '',
        ruf:       tags.ruf  || '',
        adkim:     tags.adkim || 'r',
        aspf:      tags.aspf  || 'r',
    };
}

function assessDMARC(dmarc) {
    if (!dmarc) return { status: 'missing', severity: 'crit', label: 'No DMARC record', detail: 'No DMARC record found. No policy is applied to emails that fail SPF/DKIM — spoofing is unrestricted.' };
    if (dmarc.policy === 'none')       return { status: 'warn', severity: 'warn', label: 'DMARC policy is none (monitoring only)', detail: 'Policy p=none means failed emails are not quarantined or rejected. Reporting only — no enforcement.' };
    if (dmarc.policy === 'quarantine') return { status: 'warn', severity: 'warn', label: 'DMARC policy is quarantine', detail: 'Failed emails are sent to spam/junk. Consider upgrading to p=reject for full enforcement.' };
    return { status: 'pass', severity: 'pass', label: 'DMARC enforced (p=reject)', detail: 'DMARC is set to reject. Emails failing SPF/DKIM alignment will be rejected by receiving servers.' };
}

// ─────────────────────────────────────────────────────────────
//  DKIM
// ─────────────────────────────────────────────────────────────

async function checkDKIM(domain, customSelector) {
    const selectors = customSelector
        ? [customSelector, ...DKIM_SELECTORS.filter(s => s !== customSelector)]
        : DKIM_SELECTORS;

    for (const selector of selectors) {
        const name = `${selector}._domainkey.${domain}`;
        const records = await getTXT(name);
        const match = records.find(r => r.includes('v=DKIM1') || r.includes('p='));
        if (match) {
            const hasKey = /p=[^;]+/.test(match) && !/p=;/.test(match) && !/p=""/.test(match);
            return {
                found: true,
                selector,
                record: match,
                keyPresent: hasKey,
                status: hasKey ? 'pass' : 'revoked',
            };
        }
    }
    return { found: false, selector: null, record: null, keyPresent: false, status: 'missing' };
}

function assessDKIM(dkim) {
    if (!dkim.found)           return { severity: 'warn', label: 'No DKIM key found (common selectors checked)', detail: `Checked selectors: ${DKIM_SELECTORS.join(', ')}. Try entering your selector manually.` };
    if (!dkim.keyPresent)      return { severity: 'crit', label: `DKIM key revoked (selector: ${dkim.selector})`, detail: 'The DKIM record exists but the public key (p=) is empty — this selector has been revoked.' };
    return { severity: 'pass', label: `DKIM key found (selector: ${dkim.selector})`, detail: 'A valid DKIM public key was found. Signing is likely active for this selector.' };
}

// ─────────────────────────────────────────────────────────────
//  MX
// ─────────────────────────────────────────────────────────────

async function checkMX(domain) {
    const records = await getMX(domain);
    if (!records.length) return { records: [], ips: {}, ptrs: {}, status: 'missing' };

    const ips  = {};
    const ptrs = {};

    await Promise.all(records.map(async mx => {
        const addrs = await getA(mx.host);
        ips[mx.host] = addrs;
        await Promise.all(addrs.map(async ip => {
            ptrs[ip] = await getPTR(ip);
        }));
    }));

    return { records, ips, ptrs, status: 'found' };
}

function assessMX(mx) {
    if (mx.status === 'missing') return { severity: 'crit', label: 'No MX records found', detail: 'No MX records exist for this domain. Email cannot be delivered here.' };
    const ptrIssues = Object.entries(mx.ptrs).filter(([, ptr]) => !ptr);
    if (ptrIssues.length) return { severity: 'warn', label: `${ptrIssues.length} MX server(s) missing reverse DNS`, detail: 'Missing PTR records can cause deliverability issues with strict mail filters.' };
    return { severity: 'pass', label: `${mx.records.length} MX record(s) found with reverse DNS`, detail: 'MX records resolve correctly and have PTR records configured.' };
}

// ─────────────────────────────────────────────────────────────
//  BIMI
// ─────────────────────────────────────────────────────────────

async function checkBIMI(domain) {
    const records = await getTXT(`default._bimi.${domain}`);
    const record = records.find(r => r.startsWith('v=BIMI1'));
    return record ? { found: true, record } : { found: false };
}

// ─────────────────────────────────────────────────────────────
//  BLACKLIST
// ─────────────────────────────────────────────────────────────

// DNSBL response codes:
//   127.0.0.x  = genuinely listed (x varies by list/reason)
//   127.255.255.254 = query refused / quota exceeded (Spamhaus free tier)
//   127.255.255.255 = name error / typo in zone
// Only treat as listed when the response IP is 127.0.0.x — ignore all others.
function isDNSBLListed(data) {
    if (!data?.Answer?.length) return false;
    return data.Answer.some(r => {
        if (r.type !== 1) return false;
        return /^127\.0\.0\.\d+$/.test(r.data);
    });
}

async function checkBlacklists(ips) {
    const results = [];
    const checks  = [];

    for (const ip of ips) {
        const reversed = ip.split('.').reverse().join('.');
        for (const bl of DNSBL_ZONES) {
            checks.push(
                dohLookup(`${reversed}.${bl.zone}`, 'A').then(data => {
                    results.push({ ip, zone: bl.zone, label: bl.label, listed: isDNSBLListed(data) });
                })
            );
        }
    }

    await Promise.all(checks);
    return results;
}

// ─────────────────────────────────────────────────────────────
//  TICKET NOTE
// ─────────────────────────────────────────────────────────────

function buildTicketNote(r) {
    const lines = [];
    lines.push(`=== DNS HEALTH — ${r.domain} ===`);
    lines.push(`Checked: ${r.timestamp}`);
    lines.push('');

    lines.push('[SPF]');
    lines.push(`  Status  ${r.spf.assessment.label}`);
    if (r.spf.parsed) {
        lines.push(`  Policy  ${r.spf.parsed.allLabel}`);
        lines.push(`  Lookups ${r.spf.parsed.lookupCount}/10`);
        lines.push(`  Record  ${r.spf.parsed.record}`);
    }
    lines.push('');

    lines.push('[DMARC]');
    lines.push(`  Status  ${r.dmarc.assessment.label}`);
    if (r.dmarc.parsed) {
        lines.push(`  Policy  p=${r.dmarc.parsed.policy}`);
        if (r.dmarc.parsed.pct < 100) lines.push(`  Pct     ${r.dmarc.parsed.pct}%`);
        if (r.dmarc.parsed.rua) lines.push(`  Reports ${r.dmarc.parsed.rua}`);
        lines.push(`  Record  ${r.dmarc.parsed.record}`);
    }
    lines.push('');

    lines.push('[DKIM]');
    lines.push(`  Status    ${r.dkim.assessment.label}`);
    if (r.dkim.result.found) lines.push(`  Selector  ${r.dkim.result.selector}`);
    lines.push('');

    lines.push('[MX]');
    lines.push(`  Status  ${r.mx.assessment.label}`);
    for (const rec of r.mx.result.records || []) {
        const ips = r.mx.result.ips[rec.host] || [];
        lines.push(`  ${rec.priority.toString().padEnd(4)} ${rec.host}`);
        for (const ip of ips) {
            const ptr = r.mx.result.ptrs[ip];
            lines.push(`       ${ip}  PTR: ${ptr || '(none)'}`);
        }
    }
    lines.push('');

    const listed = r.blacklists.filter(b => b.listed);
    lines.push('[BLACKLISTS]');
    if (!r.blacklistIPs.length) {
        lines.push('  No MX IPs to check.');
    } else if (!listed.length) {
        lines.push(`  Not listed on any of ${DNSBL_ZONES.length} checked blacklists.`);
    } else {
        for (const b of listed) lines.push(`  LISTED  ${b.ip} on ${b.label} (${b.zone})`);
    }
    lines.push('');
    lines.push('All checks via Cloudflare DoH. Domain names only — no client data transmitted.');
    return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────
//  ALPINE COMPONENT
// ─────────────────────────────────────────────────────────────

function dnsHealth() {
    return {
        domainInput:   '',
        selectorInput: '',
        loading:       false,
        result:        null,
        copied:        false,
        ticketNote:    '',
        inputError:    '',

        async run() {
            const domain = this.domainInput.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
            if (!domain || this.loading) return;
            const err = validateDomain(domain);
            if (err) { this.inputError = err; this.result = null; return; }
            this.inputError = '';
            this.loading = true;
            this.result  = null;

            try {
                const timestamp = new Date().toLocaleString('en-GB', {
                    day: '2-digit', month: 'short', year: 'numeric',
                    hour: '2-digit', minute: '2-digit',
                });

                // Run all checks in parallel where possible
                const [spfRecords, dmarcRecords, dkimResult, mxResult, bimiResult] = await Promise.all([
                    getTXT(domain),
                    getTXT(`_dmarc.${domain}`),
                    checkDKIM(domain, this.selectorInput.trim() || null),
                    checkMX(domain),
                    checkBIMI(domain),
                ]);

                const spfRecord   = spfRecords.find(r => r.startsWith('v=spf1'));
                const dmarcRecord = dmarcRecords.find(r => r.startsWith('v=DMARC1'));

                const spfParsed   = parseSPF(spfRecord  || null);
                const dmarcParsed = parseDMARC(dmarcRecord || null);

                const spfAssess   = assessSPF(spfParsed);
                const dmarcAssess = assessDMARC(dmarcParsed);
                const dkimAssess  = assessDKIM(dkimResult);
                const mxAssess    = assessMX(mxResult);

                // Collect all unique MX IPs for blacklist checks
                const allIPs = [...new Set(
                    Object.values(mxResult.ips).flat()
                )];

                const blacklists = allIPs.length ? await checkBlacklists(allIPs) : [];

                // Issue count — crit + warn across all checks
                const severities = [spfAssess.severity, dmarcAssess.severity, dkimAssess.severity, mxAssess.severity];
                const issueCount = severities.filter(s => s === 'crit' || s === 'warn').length
                    + blacklists.filter(b => b.listed).length;

                const r = {
                    domain,
                    timestamp,
                    issueCount,
                    spf:    { parsed: spfParsed,   assessment: spfAssess   },
                    dmarc:  { parsed: dmarcParsed, assessment: dmarcAssess },
                    dkim:   { result: dkimResult,  assessment: dkimAssess  },
                    mx:     { result: mxResult,    assessment: mxAssess    },
                    bimi:   bimiResult,
                    blacklists,
                    blacklistIPs: allIPs,
                };

                this.result     = r;
                this.ticketNote = buildTicketNote(r);
            } catch (e) {
                console.error('DNS Health check failed:', e);
            } finally {
                this.loading = false;
            }
        },

        severityClass(s) {
            return s === 'crit' ? 'text-red-400'    :
                   s === 'warn' ? 'text-yellow-400'  :
                   s === 'pass' ? 'text-emerald-400' :
                   'text-gray-400';
        },

        severityBg(s) {
            return s === 'crit' ? 'bg-red-500/10 border-red-500/20'       :
                   s === 'warn' ? 'bg-yellow-500/10 border-yellow-500/20'  :
                   s === 'pass' ? 'bg-emerald-500/10 border-emerald-500/20':
                   'bg-gray-500/10 border-gray-500/20';
        },

        severityIcon(s) {
            return s === 'crit' ? '✕' : s === 'warn' ? '!' : s === 'pass' ? '✓' : '–';
        },

        async copyNote() {
            try {
                await navigator.clipboard.writeText(this.ticketNote);
            } catch {
                const el = document.createElement('textarea');
                el.value = this.ticketNote;
                document.body.appendChild(el);
                el.select();
                document.execCommand('copy');
                document.body.removeChild(el);
            }
            this.copied = true;
            setTimeout(() => { this.copied = false; }, 2000);
        },
    };
}
