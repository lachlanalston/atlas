// ─────────────────────────────────────────────────────────────
//  ATLAS — IP Intel  |  app.js
//  All lookups run locally. No data leaves the browser.
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

const PRIVATE_RANGE_INFO = [
    { test: /^127\./,                          range: '127.0.0.0/8',      rfc: 'RFC 5735', name: 'Loopback',                purpose: 'Used by the local machine to communicate with itself. Packets sent to this range never leave the host and are not visible on the network.' },
    { test: /^10\./,                           range: '10.0.0.0/8',       rfc: 'RFC 1918', name: 'Class A Private Network', purpose: 'Large private block used in corporate and enterprise environments, data centres, and VPN address pools. Supports up to 16 million host addresses.' },
    { test: /^172\.(1[6-9]|2\d|3[01])\./,     range: '172.16.0.0/12',    rfc: 'RFC 1918', name: 'Class B Private Network', purpose: 'Mid-range private block commonly used in corporate networks, cloud VPCs, and container networking (e.g. Docker bridge networks).' },
    { test: /^192\.168\./,                     range: '192.168.0.0/16',   rfc: 'RFC 1918', name: 'Class C Private Network', purpose: 'The most common range for home and small office routers. Devices behind a NAT gateway typically receive an address in this range.' },
    { test: /^169\.254\./,                     range: '169.254.0.0/16',   rfc: 'RFC 3927', name: 'Link-local / APIPA',      purpose: 'Automatically assigned when a device fails to obtain a DHCP lease. Seeing this in logs usually indicates a network misconfiguration or DHCP failure.' },
    { test: /^::1$/,                           range: '::1/128',          rfc: 'RFC 4291', name: 'IPv6 Loopback',           purpose: 'The IPv6 equivalent of 127.0.0.1. Used by the local machine to communicate with itself; never forwarded by a router.' },
    { test: /^fd/i,                            range: 'fc00::/7 (fd::)',  rfc: 'RFC 4193', name: 'IPv6 Unique Local (fd)', purpose: 'Locally assigned IPv6 unique-local addresses. The fd:: prefix means the address was generated locally rather than centrally assigned.' },
    { test: /^fc/i,                            range: 'fc00::/7 (fc::)',  rfc: 'RFC 4193', name: 'IPv6 Unique Local (fc)', purpose: 'Centrally assigned IPv6 unique-local addresses. Comparable to RFC 1918 private space — routable within an organisation but not on the public internet.' },
];

function classifyPrivateRange(ip) {
    const match = PRIVATE_RANGE_INFO.find(e => e.test.test(ip));
    return match || { range: 'Private', rfc: 'RFC 1918', name: 'Private Address', purpose: 'This address falls within a reserved private range and is not routable on the public internet.' };
}

// ─────────────────────────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────────────────────────

function validateIP(ip) {
    // IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
        const octets = ip.split('.');
        if (octets.every(o => parseInt(o, 10) <= 255)) return null;
        return 'Invalid IPv4 address — each octet must be 0–255.';
    }
    // IPv6 — allow full, compressed (::), and mixed IPv4-in-IPv6
    if (/^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/.test(ip) ||
        /^([0-9a-fA-F]{0,4}:){1,6}:\d{1,3}(\.\d{1,3}){3}$/.test(ip) ||
        ip === '::1') return null;
    return 'Enter a valid IPv4 (e.g. 1.2.3.4) or IPv6 address.';
}

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

function buildTypeContext(result) {
    if (result.isPrivate) return {
        text:     'Private / internal address (RFC 1918). Not reachable on the public internet — belongs to a local network, VPN, or loopback interface. If you see this in a report, the traffic was captured inside the network before it hit the internet.',
        severity: 'neutral',
    };
    switch (result.type) {
        case 'cloud': return {
            text:     'Cloud infrastructure IP. The actual user or device is likely sitting behind this server — it may be a relay, proxy, VPN exit node, or hosted application. Treat the true source as unknown until you can confirm it through another channel.',
            severity: 'medium',
        };
        case 'hosting':
            if (FLAGGED_ASNS.has(result.asn)) return {
                text:     'This ASN appears on abuse tracking lists and is associated with botnets, spam infrastructure, and malicious hosting. Any activity from this IP should be treated as high risk and escalated.',
                severity: 'high',
            };
            return {
                text:     'Datacenter or hosting IP. Unlikely to belong to a residential end user — could be a VPN, proxy, self-hosted server, or anonymisation service.',
                severity: 'medium',
            };
        default: return {
            text:     `ISP / carrier IP${result.country ? ' in ' + result.country : ''}. Consistent with a residential or business internet connection — this is likely the real location of the device.`,
            severity: 'low',
        };
    }
}

function buildFlags(result) {
    const flags = [];
    if (!result) return flags;
    if (result.type === 'hosting' && FLAGGED_ASNS.has(result.asn))
        flags.push({ severity: 'high',   icon: '⚠',
            label:  'Known abuse hosting provider',
            detail: 'This ASN is listed in abuse tracking databases. It is commonly used for botnets, spam campaigns, command-and-control servers, and other malicious infrastructure. Escalate any incidents involving this IP.' });
    if (result.type === 'cloud')
        flags.push({ severity: 'medium', icon: '☁',
            label:  'Cloud provider — potential relay',
            detail: 'Cloud and hosting IPs are frequently used as relays, exit nodes, and anonymisation layers. The real origin of the traffic may be located anywhere in the world behind this server.' });
    if (['Russia', 'China', 'North Korea', 'Iran'].includes(result.country))
        flags.push({ severity: 'medium', icon: '🌐',
            label:  `Origin: ${result.country}`,
            detail: `Traffic physically originating from ${result.country} may warrant additional scrutiny depending on your organisation's risk policies and the context of the investigation.` });
    if (result.registeredCountry && result.registeredCountry !== result.country)
        flags.push({ severity: 'low',    icon: '↔',
            label:  'Country mismatch',
            detail: `The IP is physically located in ${result.country} but is registered to an organisation in ${result.registeredCountry}. This can indicate an international hosting arrangement, a CDN edge node, or traffic being routed through another country.` });
    return flags;
}

function formatTimestamp() {
    return new Date().toLocaleString('en-GB', {
        day: '2-digit', month: 'short', year: 'numeric',
        hour: '2-digit', minute: '2-digit',
    });
}

// ─────────────────────────────────────────────────────────────
//  MMDB LOADER
// ─────────────────────────────────────────────────────────────

let asnDb     = null;
let countryDb = null;

async function loadDatabases() {
    const [asnBuf, countryBuf] = await Promise.all([
        fetch('../../data/GeoLite2-ASN.mmdb').then(r => r.arrayBuffer()),
        fetch('../../data/GeoLite2-Country.mmdb').then(r => r.arrayBuffer()),
    ]);
    asnDb     = new MMDBReader(new Uint8Array(asnBuf));
    countryDb = new MMDBReader(new Uint8Array(countryBuf));
}

function performLookup(ip) {
    if (!asnDb || !countryDb) return null;

    const asnData     = asnDb.get(ip)     || {};
    const countryData = countryDb.get(ip) || {};

    const org  = asnData.autonomous_system_organization || '';
    const asn  = asnData.autonomous_system_number       || 0;
    const { type, typeLabel } = classifyIP(org, asn);

    const isPrivate = isPrivateIP(ip);

    const result = {
        ip,
        org,
        asn,
        type:              isPrivate ? 'private'          : type,
        typeLabel:         isPrivate ? 'Private / Internal' : typeLabel,
        country:           countryData.country?.names?.en            || '',
        registeredCountry: countryData.registered_country?.names?.en || '',
        continent:         countryData.continent?.names?.en           || '',
        isPrivate,
        privateRange:      isPrivate ? classifyPrivateRange(ip) : null,
        version:           ip.includes(':') ? 'IPv6' : 'IPv4',
        timestamp:         formatTimestamp(),
    };

    result.flags   = buildFlags(result);
    result.context = buildTypeContext(result);
    return result;
}

// ─────────────────────────────────────────────────────────────
//  TICKET NOTE
// ─────────────────────────────────────────────────────────────

function buildTicketNote(r) {
    const lines = [];
    lines.push(`=== IP INVESTIGATION — ${r.ip} ===`);
    lines.push(`Investigated: ${r.timestamp}`);
    lines.push('');

    if (r.isPrivate && r.privateRange) {
        lines.push(`IP Address   ${r.ip}`);
        lines.push(`Version      ${r.version}`);
        lines.push(`Visibility   Private / Internal`);
        lines.push(`Range        ${r.privateRange.range}`);
        lines.push(`Standard     ${r.privateRange.rfc}`);
        lines.push(`Type         ${r.privateRange.name}`);
        lines.push('');
        lines.push(`[NOTE]`);
        lines.push(`  ${r.privateRange.purpose}`);
        lines.push('');
        lines.push('This is a private/internal address. It is not routable on the public internet.');
        lines.push('If seen in external logs, the traffic was captured inside the network before reaching the internet.');
    } else {
        lines.push(`IP Address   ${r.ip}`);
        lines.push(`Version      ${r.version}`);
        lines.push(`Country      ${r.country || '(unknown)'}${r.continent ? ' (' + r.continent + ')' : ''}`);
        lines.push(`Organisation ${r.org     || '(unknown)'}`);
        lines.push(`ASN          ${r.asn     ? 'AS' + r.asn : '(unknown)'}`);
        lines.push(`Type         ${r.typeLabel}`);
        lines.push(`Visibility   Public`);
        if (r.registeredCountry && r.registeredCountry !== r.country)
            lines.push(`Reg. Country ${r.registeredCountry}  [MISMATCH]`);
        if (r.flags?.length) {
            lines.push('');
            lines.push('[FLAGS]');
            for (const f of r.flags) lines.push(`  ${f.icon} ${f.label}`);
        }
    }

    lines.push('');
    lines.push('All data processed locally via MaxMind GeoLite2. No external lookup performed.');
    return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────
//  ALPINE COMPONENT
// ─────────────────────────────────────────────────────────────

function ipIntel() {
    return {
        dbStatus:   'loading',
        ipInput:    '',
        ipResult:   null,
        ticketNote: '',
        copied:     false,
        inputError: '',

        async init() {
            const params = new URLSearchParams(window.location.search);
            const preIP  = params.get('ip');
            if (preIP) this.ipInput = preIP;

            try {
                await loadDatabases();
                this.dbStatus = 'ready';
                if (preIP) this.lookupIP();
            } catch (e) {
                console.error('Database load failed:', e);
                this.dbStatus = 'error';
            }
        },

        lookupIP() {
            const ip = this.ipInput.trim();
            if (!ip || this.dbStatus !== 'ready') return;
            const err = validateIP(ip);
            if (err) { this.inputError = err; this.ipResult = null; return; }
            this.inputError = '';
            const result    = performLookup(ip);
            this.ipResult   = result;
            this.ticketNote = result ? buildTicketNote(result) : 'Could not look up IP.';
            this.copied     = false;
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
