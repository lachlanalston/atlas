// ─────────────────────────────────────────────────────────────
//  ATLAS — Email Analyser  |  app.js
//  All analysis runs locally. No data leaves the browser.
// ─────────────────────────────────────────────────────────────

const FLAGGED_ASNS = new Set([
    396073, 209588, 60068, 49981, 47869, 44477, 35624,
    206264, 205100, 202425, 198605, 197695, 174, 3214,
]);

const CLOUD_ORGS = [
    'amazon', 'aws', 'microsoft', 'azure', 'google', 'gcp',
    'cloudflare', 'digitalocean', 'linode', 'vultr', 'hetzner',
    'ovh', 'scaleway', 'oracle', 'alibaba', 'tencent', 'fastly',
];

const FREE_PROVIDERS = new Set([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk',
    'hotmail.com', 'hotmail.co.uk', 'outlook.com', 'live.com',
    'icloud.com', 'me.com', 'mac.com', 'protonmail.com',
    'proton.me', 'tutanota.com', 'gmx.com', 'gmx.net',
    'mail.com', 'yandex.com', 'yandex.ru', 'aol.com',
]);

const PRIVATE_RANGES = [
    /^10\./,
    /^172\.(1[6-9]|2\d|3[01])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./,
    /^::1$/,
    /^fc/i,
    /^fd/i,
];

const URGENCY_WORDS = [
    'urgent', 'immediately', 'verify your account', 'suspended',
    'click here', 'confirm now', 'limited time', 'act now',
    'password expired', 'unusual activity', 'your account has been',
];

// ─────────────────────────────────────────────────────────────
//  IP HELPERS
// ─────────────────────────────────────────────────────────────

function isPrivateIP(ip) {
    return PRIVATE_RANGES.some(r => r.test(ip));
}

function classifyIP(org = '', asn = 0) {
    const o = org.toLowerCase();
    if (CLOUD_ORGS.some(c => o.includes(c))) return { type: 'cloud',   typeLabel: 'Cloud / Hosting' };
    if (FLAGGED_ASNS.has(asn))               return { type: 'hosting', typeLabel: 'Known Abuse Host' };
    if (o.includes('hosting') || o.includes('server') || o.includes('datacenter') || o.includes('data center'))
        return { type: 'hosting', typeLabel: 'Hosting' };
    return { type: 'isp', typeLabel: 'ISP / Carrier' };
}

function buildIPFlags(result) {
    const flags = [];
    if (!result) return flags;
    if (result.type === 'hosting' && FLAGGED_ASNS.has(result.asn))
        flags.push({ severity: 'high',   label: 'Known abuse hosting provider' });
    if (result.type === 'cloud')
        flags.push({ severity: 'medium', label: 'Cloud provider — potential relay' });
    if (['Russia', 'China', 'North Korea', 'Iran'].includes(result.country))
        flags.push({ severity: 'medium', label: `Origin: ${result.country}` });
    if (result.registeredCountry && result.registeredCountry !== result.country)
        flags.push({ severity: 'low',    label: `IP country (${result.country}) differs from registered (${result.registeredCountry})` });
    return flags;
}

// ─────────────────────────────────────────────────────────────
//  MMDB LOADER
// ─────────────────────────────────────────────────────────────

let asnDb     = null;
let countryDb = null;

async function loadDatabases() {
    const [asnBuf, countryBuf] = await Promise.all([
        fetch('/data/GeoLite2-ASN.mmdb').then(r => r.arrayBuffer()),
        fetch('/data/GeoLite2-Country.mmdb').then(r => r.arrayBuffer()),
    ]);
    asnDb     = new MMDBReader(new Uint8Array(asnBuf));
    countryDb = new MMDBReader(new Uint8Array(countryBuf));
}

function buildIPContext(r) {
    if (!r) return null;
    switch (r.type) {
        case 'cloud': return 'Cloud infrastructure IP — the sending device is likely behind this server. This could be a mail relay, VPN, or hosted mail service. The real sender location may differ significantly.';
        case 'hosting':
            if (FLAGGED_ASNS.has(r.asn)) return 'This IP belongs to an ASN flagged for abuse. Emails originating from known-abuse infrastructure are high risk and should be treated as malicious until proven otherwise.';
            return `Datacenter / hosting IP${r.country ? ' in ' + r.country : ''}. Not a typical residential sender — could be a mail server, VPN exit, or anonymisation service.`;
        default: return `ISP / carrier IP${r.country ? ' in ' + r.country : ''}. Consistent with a standard email server or end-user internet connection.`;
    }
}

function buildHopContext(hops) {
    if (!hops.length) return null;
    const n = hops.length;
    const maxDelay = Math.max(...hops.map(h => h.delay || 0));
    if (n === 1) return { text: '1 hop — direct delivery to your mail server.', warn: false };
    if (n <= 3)  return { text: `${n} hops — normal routing through a small mail chain.`, warn: false };
    if (n <= 6)  return { text: `${n} hops — slightly longer chain, but not unusual for forwarded or cloud-routed mail.`, warn: false };
    return { text: `${n} hops — unusually long delivery chain. Multiple hops can be used to obscure the true origin of an email.`, warn: true };
}

function lookupIP(ip) {
    if (!asnDb || !countryDb || isPrivateIP(ip)) return null;
    try {
        const asnData     = asnDb.get(ip)     || {};
        const countryData = countryDb.get(ip) || {};
        const org  = asnData.autonomous_system_organization || '';
        const asn  = asnData.autonomous_system_number       || 0;
        const { type, typeLabel } = classifyIP(org, asn);
        const result = {
            ip, org, asn, type, typeLabel,
            country:           countryData.country?.names?.en            || '',
            registeredCountry: countryData.registered_country?.names?.en || '',
        };
        result.flags   = buildIPFlags(result);
        result.context = buildIPContext(result);
        return result;
    } catch { return null; }
}

// ─────────────────────────────────────────────────────────────
//  DNS-OVER-HTTPS  (Cloudflare)
// ─────────────────────────────────────────────────────────────

async function dohLookup(name, type) {
    try {
        const r = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
            { headers: { 'Accept': 'application/dns-json' } }
        );
        const data = await r.json();
        // Status 0 = NOERROR, 3 = NXDOMAIN
        return {
            answers: (data.Answer || []).map(a => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, '')),
            nxdomain: data.Status === 3,
        };
    } catch {
        return { answers: [], nxdomain: false };
    }
}

function extractDKIMSelector(headers) {
    const sig = headers['dkim-signature']?.[0] || '';
    const s   = sig.match(/\bs=([^;\s]+)/)?.[1] || null;
    const d   = sig.match(/\bd=([^;\s]+)/)?.[1] || null;
    return (s && d) ? { selector: s, domain: d } : null;
}

async function checkDNSRecords(fromDomain, dkimInfo) {
    const [spfRes, dmarcRes] = await Promise.all([
        dohLookup(fromDomain, 'TXT'),
        dohLookup(`_dmarc.${fromDomain}`, 'TXT'),
    ]);

    // SPF — TXT record at the domain starting with "v=spf1"
    const spfRecord = spfRes.answers.find(r => r.startsWith('v=spf1')) || null;

    // DMARC — TXT record at _dmarc.<domain> starting with "v=DMARC1"
    const dmarcRecord = dmarcRes.answers.find(r => r.toLowerCase().startsWith('v=dmarc1')) || null;
    const dmarcPolicy = dmarcRecord?.match(/\bp=(\w+)/i)?.[1]?.toLowerCase() || null;
    const dmarcRua    = dmarcRecord?.match(/\brua=([^;]+)/i)?.[1] || null;
    const dmarcPct    = dmarcRecord?.match(/\bpct=(\d+)/i)?.[1]   || '100';

    // DKIM — TXT record at <selector>._domainkey.<domain>
    let dkim = null;
    if (dkimInfo) {
        const lookupName = `${dkimInfo.selector}._domainkey.${dkimInfo.domain}`;
        const dkimRes = await dohLookup(lookupName, 'TXT');
        const keyRecord = dkimRes.answers.find(r => r.includes('p=')) || null;
        dkim = {
            lookupName,
            exists:  !!keyRecord,
            revoked: keyRecord === 'v=DKIM1; p=' || keyRecord?.includes('p=;') || false,
        };
    }

    return { domain: fromDomain, spfRecord, dmarcRecord, dmarcPolicy, dmarcRua, dmarcPct, dkim };
}

// ─────────────────────────────────────────────────────────────
//  EMAIL PARSER
// ─────────────────────────────────────────────────────────────

function parseHeaders(raw) {
    const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
    const headers  = {};
    for (const line of unfolded.split(/\r?\n/)) {
        const m = line.match(/^([\w\-]+):\s*(.*)$/i);
        if (m) {
            const key = m[1].toLowerCase();
            if (!headers[key]) headers[key] = [];
            headers[key].push(m[2].trim());
        }
    }
    return headers;
}

// ─────────────────────────────────────────────────────────────
//  AUTH EXPLANATIONS
//  Dynamic, plain-English descriptions for each check + result.
// ─────────────────────────────────────────────────────────────

const AUTH_META = {
    SPF: {
        what: 'SPF (Sender Policy Framework) checks whether the server that delivered this email is authorised to send on behalf of the domain in the return-path.',
        results: {
            'pass':      { short: 'Authorised sender',          detail: 'The server that delivered this email is listed as an approved sender for this domain. This check passed cleanly.',                                                                              severity: 'pass'    },
            'fail':      { short: 'Unauthorised sender',         detail: 'The delivering server is not allowed to send for this domain. This is a strong indicator the email is spoofed — it didn\'t come from who it claims.',                                          severity: 'fail'    },
            'softfail':  { short: 'Sender not fully authorised', detail: 'The server isn\'t in the approved list but the domain uses a soft-fail policy (~all), so it wasn\'t rejected. The email is suspicious — verify with the sender through a different channel.',  severity: 'warn'    },
            'neutral':   { short: 'Domain takes no position',    detail: 'The domain owner has stated they can\'t confirm whether this server is authorised. Not an automatic red flag, but gives no reassurance either.',                                                severity: 'neutral' },
            'none':      { short: 'No SPF record exists',        detail: 'This domain has no SPF record, so no check was performed. Anyone can send email claiming to be from this domain. Look at DKIM and DMARC for additional context.',                              severity: 'neutral' },
            'permerror': { short: 'SPF record is broken',        detail: 'The domain\'s SPF record has a configuration error and couldn\'t be evaluated. The result is inconclusive — escalate if other signals are present.',                                           severity: 'warn'    },
            'temperror': { short: 'Temporary DNS failure',       detail: 'The SPF check couldn\'t complete due to a temporary DNS error. This isn\'t necessarily suspicious — a retry would likely work. Don\'t use this result alone to make a decision.',              severity: 'neutral' },
            'missing':   { short: 'Not reported in these headers', detail: 'No SPF result was found. This usually means you\'re viewing the condensed display headers, not the full raw headers. In Outlook: File → Properties → Internet headers. In Gmail: three dots → Show original.', severity: 'neutral' },
        },
    },
    DKIM: {
        what: 'DKIM (DomainKeys Identified Mail) verifies that the email content hasn\'t been altered in transit by checking a cryptographic signature added by the sending server.',
        results: {
            'pass':      { short: 'Signature is valid',           detail: 'The email carries a valid digital signature. This confirms the content hasn\'t been tampered with since it was sent, and the sending domain authorised it.',                                   severity: 'pass'    },
            'fail':      { short: 'Signature is invalid',         detail: 'The digital signature doesn\'t verify. The email may have been modified in transit, or the signature key doesn\'t match. Treat this email with high suspicion.',                              severity: 'fail'    },
            'neutral':   { short: 'Signature is inconclusive',    detail: 'DKIM was checked but the result is inconclusive — neither a pass nor a definitive fail. Not alarming on its own but worth noting.',                                                           severity: 'neutral' },
            'none':      { short: 'No signature present',         detail: 'The email wasn\'t signed with DKIM. This is common from older or simpler mail systems but means you can\'t verify the email hasn\'t been modified. Not suspicious by itself.',                severity: 'neutral' },
            'permerror': { short: 'DKIM configuration error',     detail: 'The DKIM signature couldn\'t be verified due to a permanent configuration error (e.g. malformed signature, missing key). The result is inconclusive.',                                        severity: 'warn'    },
            'temperror': { short: 'Temporary verification error', detail: 'DKIM verification failed temporarily, likely due to a DNS issue. Not necessarily suspicious on its own.',                                                                                     severity: 'neutral' },
            'missing':   { short: 'Not reported in these headers', detail: 'No DKIM result was found. Paste the full raw headers from your email client to see this result.',                                                                                            severity: 'neutral' },
        },
    },
    DMARC: {
        what: 'DMARC (Domain-based Message Authentication, Reporting and Conformance) is the overall policy check. It passes only if the From address aligns with a passing SPF or DKIM result. This is the hardest check to fake.',
        results: {
            'pass':         { short: 'Domain policy met',              detail: 'The email passed the domain\'s DMARC policy. The From address aligns with the SPF or DKIM result. This is the strongest single indicator that the email is legitimate.',                    severity: 'pass'    },
            'fail':         { short: 'Domain policy NOT met',          detail: 'The email failed DMARC. The From address doesn\'t align with the SPF or DKIM results. This is a strong indicator of spoofing. If the domain has a reject policy, this email should not have been delivered at all — flag it.',  severity: 'fail'    },
            'bestguesspass':{ short: 'Passed (no policy enforced)',    detail: 'The email passed DMARC on a best-effort basis, but the domain has no published DMARC record. Without a policy there\'s no enforcement, so this pass doesn\'t carry much weight.',          severity: 'neutral' },
            'none':         { short: 'No DMARC record',                detail: 'No DMARC policy exists for this domain, so nothing is enforced. This means even a spoofed email wouldn\'t be blocked. Combined with SPF or DKIM failures, this is a significant gap.',     severity: 'neutral' },
            'permerror':    { short: 'DMARC record is broken',         detail: 'The DMARC record couldn\'t be evaluated due to a configuration error. Result is inconclusive.',                                                                                            severity: 'warn'    },
            'temperror':    { short: 'Temporary evaluation error',     detail: 'DMARC evaluation failed due to a temporary DNS issue. Not necessarily suspicious on its own.',                                                                                            severity: 'neutral' },
            'missing':      { short: 'Not reported in these headers',  detail: 'No DMARC result was found in these headers. Paste the full raw headers from your email client to see this result.',                                                                        severity: 'neutral' },
        },
    },
};

function getAuthExplanation(label, result, found) {
    const meta    = AUTH_META[label];
    const key     = !found ? 'missing' : (result || 'none');
    const info    = meta.results[key] || meta.results['missing'];
    return { what: meta.what, ...info };
}

function extractAuth(headers) {
    // Merge all authentication result sources — different mail servers use different headers:
    //   Authentication-Results      — standard RFC 7601
    //   ARC-Authentication-Results  — Google, Microsoft (ARC chain)
    //   X-MS-Exchange-Authentication-Results — older Outlook/Exchange
    const ar = [
        ...(headers['authentication-results']               || []),
        ...(headers['arc-authentication-results']           || []),
        ...(headers['x-ms-exchange-authentication-results'] || []),
    ].join(' ').toLowerCase();

    const hasAr = ar.trim().length > 0;

    const spfResult   = ar.match(/spf=(pass|fail|softfail|neutral|permerror|temperror)/)?.[1]  || null;
    const dkimResult  = ar.match(/dkim=(pass|fail|neutral|permerror|temperror)/)?.[1]           || null;
    const dmarcResult = ar.match(/dmarc=(pass|fail|bestguesspass|permerror|temperror)/)?.[1]    || null;

    // Fallback: Received-SPF is a dedicated SPF result header many servers add
    let spfFinal = spfResult;
    if (!spfFinal) {
        const rspf = (headers['received-spf'] || []).join(' ').toLowerCase();
        spfFinal = rspf.match(/^(pass|fail|softfail|neutral|permerror|temperror)/)?.[1] || null;
    }

    const checks = [
        { label: 'SPF',   result: spfFinal   || 'none', pass: spfFinal   === 'pass', found: hasAr || !!spfFinal },
        { label: 'DKIM',  result: dkimResult  || 'none', pass: dkimResult  === 'pass', found: hasAr },
        { label: 'DMARC', result: dmarcResult || 'none', pass: dmarcResult === 'pass', found: hasAr },
    ];

    return checks.map(c => ({ ...c, explanation: getAuthExplanation(c.label, c.result, c.found) }));
}

function extractHops(headers) {
    const received = headers['received'] || [];
    const hops     = [];
    for (const r of received) {
        const fromMatch = r.match(/from\s+([^\s;(\[]+)/i);
        // IP in brackets is the verified connecting IP added by the receiving server
        const ipMatch   = r.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
        const tsMatch   = r.match(/;\s*(.+)$/);
        const ts        = tsMatch ? tsMatch[1].trim() : null;
        let delay       = null;
        if (hops.length > 0 && ts && hops[hops.length - 1]?.rawTs) {
            const prev = new Date(hops[hops.length - 1].rawTs).getTime();
            const curr = new Date(ts).getTime();
            if (!isNaN(prev) && !isNaN(curr))
                delay = Math.max(0, Math.round((prev - curr) / 1000));
        }
        hops.push({
            from:      fromMatch?.[1] || null,
            ip:        ipMatch?.[1]   || null,
            timestamp: ts || '(no timestamp)',
            rawTs:     ts,
            delay,
        });
    }
    return hops.reverse();
}

// Extract the originating IP specifically from Received headers.
// Received headers are stacked newest-first; the last one is the origin.
// The connecting IP is always in square brackets added by the receiving server.
function extractOriginIP(received) {
    // Walk from oldest hop (last element) toward newest — stop at first public IP
    for (let i = received.length - 1; i >= 0; i--) {
        const r = received[i];
        // All bracketed IPv4 addresses in this header
        const matches = [...r.matchAll(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/g)];
        for (const m of matches) {
            if (!isPrivateIP(m[1])) return m[1];
        }
    }
    // Fallback: any bare IPv4 in the oldest Received header that isn't private
    for (let i = received.length - 1; i >= 0; i--) {
        const ips = received[i].match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) || [];
        const pub = ips.find(ip => !isPrivateIP(ip));
        if (pub) return pub;
    }
    return null;
}

function extractDomain(email = '') {
    return email.match(/@([\w.\-]+)/)?.[1]?.toLowerCase() || null;
}

function detectSignals(headers, auth, originIP) {
    const signals   = [];
    const from      = (headers['from']?.[0]    || '').toLowerCase();
    const replyTo   = (headers['reply-to']?.[0] || '').toLowerCase();
    const subject   = (headers['subject']?.[0]  || '').toLowerCase();

    // Auth failures
    if (auth.find(a => a.label === 'DKIM'  && !a.pass && a.result !== 'none'))
        signals.push({ severity: 'high',   label: 'DKIM failed',  detail: 'Email content may have been tampered with in transit.' });
    if (auth.find(a => a.label === 'SPF'   && !a.pass && a.result !== 'none'))
        signals.push({ severity: 'high',   label: 'SPF failed',   detail: 'Sending server is not authorised to send for this domain.' });
    if (auth.find(a => a.label === 'DMARC' && !a.pass && a.result !== 'none'))
        signals.push({ severity: 'high',   label: 'DMARC failed', detail: 'Domain owner policy not met — strong indicator of spoofing.' });

    // Reply-To mismatch
    if (replyTo && from) {
        const fd = extractDomain(from);
        const rd = extractDomain(replyTo);
        if (fd && rd && fd !== rd)
            signals.push({ severity: 'high', label: 'Reply-To domain mismatch', detail: `From: ${fd} · Reply-To: ${rd}` });
    }

    // Free provider
    const fromDomain = extractDomain(from);
    if (fromDomain && FREE_PROVIDERS.has(fromDomain))
        signals.push({ severity: 'medium', label: `Free email provider (${fromDomain})`, detail: 'Legitimate business email rarely originates from free providers.' });

    // Urgency keywords
    const found = URGENCY_WORDS.filter(w => subject.includes(w));
    if (found.length)
        signals.push({ severity: 'medium', label: 'Urgency language in subject', detail: `Matched: ${found.join(', ')}` });

    // IP flags
    if (originIP?.flags?.length) {
        for (const f of originIP.flags)
            signals.push({ severity: f.severity, label: `Origin IP: ${f.label}`, detail: `${originIP.ip} — ${originIP.country || 'unknown country'}` });
    }

    return signals;
}

// ─────────────────────────────────────────────────────────────
//  TIMELINE ANALYSIS
// ─────────────────────────────────────────────────────────────

function formatDelta(secs) {
    const abs = Math.abs(secs);
    if (abs < 60)    return `${abs}s`;
    if (abs < 3600)  return `${Math.round(abs / 60)}m`;
    if (abs < 86400) return `${Math.round(abs / 3600)}h`;
    return `${Math.round(abs / 86400)}d`;
}

function analyseTimeline(headers, hops) {
    const dateStr = headers['date']?.[0] || null;
    if (!dateStr) return null;

    const sentMs = new Date(dateStr).getTime();
    if (isNaN(sentMs)) return null;

    // After hops are reversed (oldest→newest), the last element is the most recent hop
    const newestHop    = hops.length ? hops[hops.length - 1] : null;
    const receivedMs   = newestHop?.rawTs ? new Date(newestHop.rawTs).getTime() : NaN;
    const hasReceived  = !isNaN(receivedMs);

    const deltaSecs    = hasReceived ? Math.round((receivedMs - sentMs) / 1000) : null;

    // Format the sent date for display
    let sentDisplay = dateStr;
    try { sentDisplay = new Date(dateStr).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }); } catch {}

    let receivedDisplay = null;
    if (hasReceived) {
        try { receivedDisplay = new Date(receivedMs).toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' }); } catch {}
    }

    // Determine flag
    let flag = null;
    if (deltaSecs !== null) {
        if (deltaSecs < -300) {
            // Date header is more than 5 minutes in the future — very suspicious
            flag = {
                severity: 'high',
                label:    'Date header is set in the future',
                detail:   `The Date header is ${formatDelta(deltaSecs)} ahead of when the email was actually delivered. Legitimate mail servers use accurate system clocks — this is a strong indicator of header manipulation or a spoofing tool.`,
            };
        } else if (deltaSecs > 86400 * 2) {
            // More than 2 days — significant backdating
            flag = {
                severity: 'medium',
                label:    `Sent date is ${formatDelta(deltaSecs)} before delivery`,
                detail:   `The Date header is significantly earlier than actual delivery. This may indicate the email was backdated to appear older, or was stuck in a queue for an unusual amount of time.`,
            };
        } else if (deltaSecs > 3600 * 4) {
            // 4+ hours — notable but could be greylisting/queue
            flag = {
                severity: 'low',
                label:    `Delivery took ${formatDelta(deltaSecs)}`,
                detail:   `There is a ${formatDelta(deltaSecs)} gap between the sent date and delivery. This can be caused by server greylisting, retry queues, or in some cases, header manipulation.`,
            };
        }
    }

    return { sentDisplay, receivedDisplay, deltaSecs, flag };
}

// ─────────────────────────────────────────────────────────────
//  HEADER VALIDATION
// ─────────────────────────────────────────────────────────────

const CORE_HEADERS    = new Set(['from', 'to', 'cc', 'date', 'subject', 'message-id', 'received', 'return-path', 'reply-to']);
const MINIMUM_MATCHES = 2;

function validateEmailHeaders(headers) {
    const keys         = Object.keys(headers);
    const coreMatches  = keys.filter(k => CORE_HEADERS.has(k));
    const totalHeaders = keys.length;

    if (totalHeaders === 0) {
        return {
            valid:   false,
            code:    'no_headers',
            message: 'No headers found.',
            detail:  'Nothing recognisable was parsed from the input. Make sure you\'re pasting the raw email headers, not the email body or a screenshot.',
        };
    }

    if (coreMatches.length < MINIMUM_MATCHES) {
        return {
            valid:   false,
            code:    'insufficient_headers',
            message: `This doesn't look like email headers.`,
            detail:  totalHeaders === 1
                ? `Only one header-like line was found (${keys[0]}). Email headers contain many fields — paste the full block of raw headers from your email client.`
                : `Found ${totalHeaders} header-like line${totalHeaders > 1 ? 's' : ''} but none of the standard email fields (From, To, Date, Subject, Received, Message-ID). You may have pasted the email body instead of the headers.`,
        };
    }

    // Valid — optionally warn if key analysis headers are missing
    const hasReceived = headers['received']?.length > 0;
    const hasFrom     = !!headers['from']?.[0];
    const hasDate     = !!headers['date']?.[0];

    if (!hasReceived && !hasFrom && !hasDate) {
        return {
            valid:   true,
            warning: true,
            message: 'Headers are incomplete.',
            detail:  'The From, Date, and Received headers are all missing. Routing and authentication analysis will be limited.',
        };
    }

    return { valid: true, warning: false };
}

function scoreSignals(signals) {
    return Math.min(100, signals.reduce((acc, s) => {
        return acc + (s.severity === 'high' ? 30 : s.severity === 'medium' ? 15 : 5);
    }, 0));
}

function getVerdict(score) {
    if (score >= 60) return { verdict: 'PHISHING',   verdictLabel: 'Likely Phishing',      verdictDetail: 'Multiple high-confidence indicators detected. Treat as malicious.' };
    if (score >= 25) return { verdict: 'SUSPICIOUS', verdictLabel: 'Suspicious',            verdictDetail: 'Some indicators present. Exercise caution and verify with the sender.' };
    return           { verdict: 'CLEAN',     verdictLabel: 'No Issues Detected',    verdictDetail: 'No phishing signals found. Standard handling applies.' };
}

// ─────────────────────────────────────────────────────────────
//  TICKET NOTE
// ─────────────────────────────────────────────────────────────

function buildTicketNote(result, headers) {
    const from    = headers['from']?.[0]    || '(unknown)';
    const subject = headers['subject']?.[0] || '(unknown)';
    const date    = headers['date']?.[0]    || '(unknown)';
    const lines   = [];

    lines.push('=== EMAIL HEADER ANALYSIS ===');
    lines.push(`Analysed: ${new Date().toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' })}`);
    lines.push('');
    lines.push('[VERDICT]');
    lines.push(`  ${result.verdictLabel.toUpperCase()}  —  Score: ${result.score}/100`);
    lines.push(`  ${result.verdictDetail}`);
    lines.push('');
    lines.push('[EMAIL DETAILS]');
    lines.push(`  From      ${from}`);
    lines.push(`  Subject   ${subject}`);
    lines.push(`  Sent      ${date}`);
    if (result.timeline?.receivedDisplay)
        lines.push(`  Delivered ${result.timeline.receivedDisplay}${result.timeline.deltaSecs !== null ? '  (+' + formatDelta(result.timeline.deltaSecs) + ' transit)' : ''}`);
    if (result.timeline?.flag)
        lines.push(`  [${result.timeline.flag.severity.toUpperCase()}] ${result.timeline.flag.label}`);
    lines.push('');
    lines.push('[AUTHENTICATION]');
    for (const a of result.auth)
        lines.push(`  ${a.label.padEnd(6)} ${a.result.toUpperCase()}`);
    lines.push('');
    if (result.originIP) {
        lines.push('[ORIGINATING IP]');
        lines.push(`  IP           ${result.originIP.ip}`);
        lines.push(`  Country      ${result.originIP.country || '(unknown)'}`);
        lines.push(`  Organisation ${result.originIP.org     || '(unknown)'}`);
        lines.push(`  ASN          ${result.originIP.asn ? 'AS' + result.originIP.asn : '(unknown)'}`);
        lines.push('');
    }
    if (result.dnsRecords) {
        const d = result.dnsRecords;
        lines.push('[DNS RECORDS]');
        lines.push(`  SPF    ${d.spfRecord  || '(no record)'}`) ;
        lines.push(`  DMARC  ${d.dmarcRecord ? `p=${d.dmarcPolicy} pct=${d.dmarcPct}${d.dmarcRua ? ' rua=' + d.dmarcRua : ''}` : '(no record)'}`);
        if (d.dkim)
            lines.push(`  DKIM   ${d.dkim.exists ? (d.dkim.revoked ? 'Key revoked — ' : 'Key found — ') + d.dkim.lookupName : 'No key at ' + d.dkim.lookupName}`);
        lines.push('');
    }
    if (result.signals?.length) {
        lines.push('[SIGNALS]');
        for (const s of result.signals)
            lines.push(`  [${s.severity.toUpperCase()}] ${s.label} — ${s.detail}`);
        lines.push('');
    }
    lines.push('All data processed locally. DNS queries via Cloudflare DoH (domain names only — no email content sent).');
    return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────
//  ALPINE COMPONENT
// ─────────────────────────────────────────────────────────────

function emailAnalyser() {
    return {
        dbStatus:      'loading',
        emailInput:    '',
        result:        null,
        headerError:   null,
        headerWarning: null,
        ticketNote:    '',
        copied:        false,
        dnsLoading:    false,
        _headers:      null,

        formatDelta,  // expose for template use

        async init() {
            try {
                await loadDatabases();
                this.dbStatus = 'ready';
            } catch (e) {
                console.error('Database load failed:', e);
                this.dbStatus = 'error';
            }
        },

        async analyse() {
            const raw = this.emailInput.trim();
            if (!raw || this.dbStatus !== 'ready') return;

            const headers    = parseHeaders(raw);
            this._headers    = headers;
            this.headerError = null;
            this.headerWarning = null;

            const validation = validateEmailHeaders(headers);
            if (!validation.valid) {
                this.headerError = validation;
                this.result      = null;
                return;
            }
            if (validation.warning) {
                this.headerWarning = validation;
            }

            const auth        = extractAuth(headers);
            const hops        = extractHops(headers);
            const originIPStr = extractOriginIP(headers['received'] || []);
            const originIP    = originIPStr ? lookupIP(originIPStr) : null;

            console.debug('[Atlas] parsed headers:', Object.keys(headers));
            console.debug('[Atlas] received count:', (headers['received'] || []).length);
            console.debug('[Atlas] origin IP:', originIPStr, '→', originIP);

            const from    = headers['from']?.[0]     || '';
            const replyTo = headers['reply-to']?.[0] || '';

            const senderFields = [
                { label: 'From',     value: from,    flag: false, flagReason: '' },
                { label: 'Reply-To', value: replyTo, flag: false, flagReason: '' },
            ];

            if (replyTo && from) {
                const fd = extractDomain(from.toLowerCase());
                const rd = extractDomain(replyTo.toLowerCase());
                if (fd && rd && fd !== rd) {
                    senderFields[1].flag       = true;
                    senderFields[1].flagReason = `Domain differs from From (${fd})`;
                }
            }

            const timeline = analyseTimeline(headers, hops);
            const signals  = detectSignals(headers, auth, originIP);
            if (timeline?.flag) signals.push(timeline.flag);

            const score    = scoreSignals(signals);
            const verdict  = getVerdict(score);
            const hopContext = buildHopContext(hops);

            // Show header analysis immediately
            this.result     = { ...verdict, score, auth, hops, hopContext, timeline, originIP, senderFields, signals, dnsRecords: null };
            this.ticketNote = buildTicketNote(this.result, headers);
            this.copied     = false;

            // DNS checks — async, fills in after header results appear
            const fromDomain = extractDomain(from.toLowerCase());
            if (fromDomain) {
                this.dnsLoading = true;
                try {
                    const dkimInfo   = extractDKIMSelector(headers);
                    const dnsRecords = await checkDNSRecords(fromDomain, dkimInfo);
                    this.result      = { ...this.result, dnsRecords };
                    this.ticketNote  = buildTicketNote(this.result, headers);
                } catch (e) {
                    console.error('[Atlas] DNS check failed:', e);
                } finally {
                    this.dnsLoading = false;
                }
            }
        },

        clear() {
            this.emailInput    = '';
            this.result        = null;
            this.headerError   = null;
            this.headerWarning = null;
            this.copied        = false;
            this._headers      = null;
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
