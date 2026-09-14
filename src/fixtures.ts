/**
 * Synthetic RUA corpus with PLANTED faults, emitted in five providers' dialects.
 *
 * Every fault below has a known ground truth exported alongside the XML, so the
 * suite can assert that the analyser recovers the truth - and, separately, that
 * the naive open-rate reading does not.
 *
 * Planted faults:
 *   F1  mail.insurer-example.com  - the ESP repoints its bounce (envelope) domain
 *       on BREAK_DAY, so SPF still PASSES but no longer ALIGNS. The stream is
 *       SPF-only (no DKIM), so DMARC starts failing and p=quarantine suppresses
 *       it. This is the deliverability incident.
 *   F2  203.0.113.55 - a third-party ESP that was never authorised, sending as
 *       the root domain with no alignment evidence at all, at volume. Spoofing.
 *   F3  192.0.2.77 - an unfamiliar IP holding a VALID ALIGNED DKIM key. Not in
 *       the inventory, but cryptographically authorised: a new vendor someone
 *       onboarded without telling the mail team. Must NOT be called spoofing.
 *   F4  claims.insurer-example.com - a legitimate sender whose DKIM signature
 *       broke at a key rotation but whose SPF still aligns. DMARC therefore
 *       PASSES and the mail is delivered. Must NOT appear as a deliverability
 *       incident, only as an authentication-hygiene warning.
 *   F5  five forwarder IPs emitting a handful of unaligned failures a day, the
 *       background noise any real domain sees. Must NOT be flagged.
 */

import type { EngagementDay } from './analyse.ts';

// --- deterministic RNG -----------------------------------------------------

function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function gaussian(rnd: () => number): number {
  // Box-Muller. Guarded against log(0), which would produce Infinity.
  const u = Math.max(rnd(), Number.MIN_VALUE);
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * rnd());
}

/** Normal approximation to Binomial(n, p); exact sampling is not worth the ms at n ~ 1e4. */
function binomial(n: number, p: number, rnd: () => number): number {
  if (n <= 0) return 0;
  const mean = n * p;
  const sd = Math.sqrt(n * p * (1 - p));
  return Math.max(0, Math.min(n, Math.round(mean + sd * gaussian(rnd))));
}

// --- scenario constants ----------------------------------------------------

export const DOMAIN = 'insurer-example.com';
export const MARKETING_SUBDOMAIN = `mail.${DOMAIN}`;
export const CLAIMS_SUBDOMAIN = `claims.${DOMAIN}`;
export const SURVEY_SUBDOMAIN = `survey.${DOMAIN}`;

const START_DAY = '2026-02-24';
export const BREAK_DAY = '2026-03-10';
const DAYS = 29;

/** True open rate among people who actually received the mail. Constant by construction. */
export const TRUE_OPEN_RATE = 0.24;

/**
 * Share of the marketing stream that moved to the new (misaligned) bounce
 * domain after the break. Not 100%: the ESP migrated a pool at a time, which is
 * what makes the incident survivable long enough for someone to blame the
 * subject lines instead.
 */
const BROKEN_SHARE_AFTER = 0.85;

export const AUTHORISED_IPS = ['198.51.100.10', '198.51.100.20', '198.51.100.30'];
const ESP_IP = '198.51.100.10';
const CORP_IP = '198.51.100.20';
const CLAIMS_IP = '198.51.100.30';
export const SPOOF_IP = '203.0.113.55';
export const NEW_VENDOR_IP = '192.0.2.77';
export const FORWARDER_IPS = ['100.64.3.11', '100.64.7.42', '100.64.19.8', '100.64.22.5', '100.64.31.77'];

/** Rough mailbox-provider geography, for the volume+geography view. */
export const GEO: Record<string, string> = {
  '198.51.100.10': 'US-East',
  '198.51.100.20': 'GB-London',
  '198.51.100.30': 'GB-London',
  '203.0.113.55': 'RU-Moscow',
  '192.0.2.77': 'IE-Dublin',
  '100.64.3.11': 'US-West',
  '100.64.7.42': 'DE-Frankfurt',
  '100.64.19.8': 'US-East',
  '100.64.22.5': 'FR-Paris',
  '100.64.31.77': 'NL-Amsterdam',
};

export type ProviderName = 'google' | 'microsoft' | 'yahoo' | 'mimecast' | 'fastmail';

const PROVIDERS: { name: ProviderName; share: number }[] = [
  { name: 'google', share: 0.42 },
  { name: 'microsoft', share: 0.28 },
  { name: 'yahoo', share: 0.14 },
  { name: 'mimecast', share: 0.09 },
  { name: 'fastmail', share: 0.07 },
];

// --- intermediate (provider-neutral) record shape ---------------------------

type GenRecord = {
  ip: string;
  count: number;
  disposition: 'none' | 'quarantine' | 'reject';
  dkimEval: 'pass' | 'fail';
  spfEval: 'pass' | 'fail';
  headerFrom: string;
  envelopeFrom?: string;
  dkim: { domain: string; selector?: string; result: string }[];
  spf: { domain: string; result: string }[];
};

function dayToEpoch(day: string): number {
  return Math.floor(Date.parse(`${day}T00:00:00Z`) / 1000);
}

function addDays(day: string, n: number): string {
  return new Date(Date.parse(`${day}T00:00:00Z`) + n * 86400_000).toISOString().slice(0, 10);
}

// --- XML emitters, one per provider dialect --------------------------------

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function emitGoogle(day: string, records: GenRecord[], seq: number): string {
  const b = dayToEpoch(day);
  const rows = records
    .map(
      (r) => `  <record>
    <row>
      <source_ip>${r.ip}</source_ip>
      <count>${r.count}</count>
      <policy_evaluated>
        <disposition>${r.disposition}</disposition>
        <dkim>${r.dkimEval}</dkim>
        <spf>${r.spfEval}</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>${r.headerFrom}</header_from>
    </identifiers>
    <auth_results>
${r.dkim
  .map(
    (d) => `      <dkim>
        <domain>${d.domain}</domain>
        <selector>${d.selector ?? 's1'}</selector>
        <result>${d.result}</result>
      </dkim>`,
  )
  .join('\n')}
${r.spf
  .map(
    (s) => `      <spf>
        <domain>${s.domain}</domain>
        <scope>mfrom</scope>
        <result>${s.result}</result>
      </spf>`,
  )
  .join('\n')}
    </auth_results>
  </record>`,
    )
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <extra_contact_info>https://support.google.com/a/answer/2466580</extra_contact_info>
    <report_id>${seq}${day.replace(/-/g, '')}</report_id>
    <date_range>
      <begin>${b}</begin>
      <end>${b + 86399}</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>${DOMAIN}</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>quarantine</p>
    <sp>quarantine</sp>
    <pct>100</pct>
  </policy_published>
${rows}
</feedback>
`;
}

/** Microsoft: Title-Case results, no <selector>, no <pct>, identifiers BEFORE row. */
function emitMicrosoft(day: string, records: GenRecord[], seq: number): string {
  const b = dayToEpoch(day);
  const tc = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
  const rows = records
    .map(
      (r) => `  <record>
    <identifiers>
      <envelope_to>contoso.com</envelope_to>
      ${r.envelopeFrom ? `<envelope_from>${r.envelopeFrom}</envelope_from>` : ''}
      <header_from>${r.headerFrom}</header_from>
    </identifiers>
    <auth_results>
${r.spf.map((s) => `      <spf><domain>${s.domain}</domain><result>${tc(s.result)}</result></spf>`).join('\n')}
${r.dkim.map((d) => `      <dkim><domain>${d.domain}</domain><result>${tc(d.result)}</result></dkim>`).join('\n')}
    </auth_results>
    <row>
      <source_ip>${r.ip}</source_ip>
      <count>${r.count}</count>
      <policy_evaluated>
        <disposition>${r.disposition}</disposition>
        <dkim>${tc(r.dkimEval)}</dkim>
        <spf>${tc(r.spfEval)}</spf>
      </policy_evaluated>
    </row>
  </record>`,
    )
    .join('\n');
  return `<?xml version="1.0" encoding="utf-8"?>
<feedback>
  <report_metadata>
    <org_name>Enterprise Outlook</org_name>
    <email>dmarcreport@microsoft.com</email>
    <report_id>${seq}-ms-${day}</report_id>
    <date_range><begin>${b}</begin><end>${b + 86399}</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>${DOMAIN}</domain>
    <p>quarantine</p>
    <sp>quarantine</sp>
  </policy_published>
${rows}
</feedback>
`;
}

/** Yahoo: <end> before <begin>, self-closing <error/>, no <scope>, a comment. */
function emitYahoo(day: string, records: GenRecord[], seq: number): string {
  const b = dayToEpoch(day);
  const rows = records
    .map(
      (r) => `  <record>
    <row><source_ip>${r.ip}</source_ip><count>${r.count}</count>
      <policy_evaluated><disposition>${r.disposition}</disposition><dkim>${r.dkimEval}</dkim><spf>${r.spfEval}</spf></policy_evaluated>
    </row>
    <identifiers><header_from>${r.headerFrom}</header_from></identifiers>
    <auth_results>
${r.dkim.map((d) => `      <dkim><domain>${d.domain}</domain><result>${d.result}</result><human_result></human_result></dkim>`).join('\n')}
${r.spf.map((s) => `      <spf><domain>${s.domain}</domain><result>${s.result}</result></spf>`).join('\n')}
    </auth_results>
  </record>`,
    )
    .join('\n');
  return `<?xml version="1.0"?>
<!-- generated by dmarc-aggregator -->
<feedback>
  <report_metadata>
    <org_name>Yahoo</org_name>
    <email>dmarchelp@yahooinc.com</email>
    <report_id>${seq}.${day.replace(/-/g, '')}</report_id>
    <date_range><end>${b + 86399}</end><begin>${b}</begin></date_range>
    <error/>
  </report_metadata>
  <policy_published><domain>${DOMAIN}</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>quarantine</sp><pct>100</pct><fo>1</fo></policy_published>
${rows}
</feedback>
`;
}

/** Mimecast-style gateway: namespace prefix on every element, CDATA org name. */
function emitMimecast(day: string, records: GenRecord[], seq: number): string {
  const b = dayToEpoch(day);
  const rows = records
    .map(
      (r) => `  <dm:record>
    <dm:row><dm:source_ip>${r.ip}</dm:source_ip><dm:count> ${r.count} </dm:count>
      <dm:policy_evaluated><dm:disposition>${r.disposition}</dm:disposition><dm:dkim>${r.dkimEval}</dm:dkim><dm:spf>${r.spfEval}</dm:spf></dm:policy_evaluated></dm:row>
    <dm:identifiers><dm:header_from>${r.headerFrom}</dm:header_from></dm:identifiers>
    <dm:auth_results>
${r.dkim.map((d) => `      <dm:dkim><dm:domain>${d.domain}</dm:domain><dm:selector>${d.selector ?? 'mc1'}</dm:selector><dm:result>${d.result}</dm:result></dm:dkim>`).join('\n')}
${r.dkim.length > 0 ? `      <dm:dkim><dm:domain>mimecast-relay.net</dm:domain><dm:selector>mc-relay</dm:selector><dm:result>pass</dm:result></dm:dkim>` : ''}
${r.spf.map((s) => `      <dm:spf><dm:domain>${s.domain}</dm:domain><dm:scope>mfrom</dm:scope><dm:result>${s.result}</dm:result></dm:spf>`).join('\n')}
    </dm:auth_results>
  </dm:record>`,
    )
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<dm:feedback xmlns:dm="http://dmarc.org/dmarc-xml/0.1">
  <dm:report_metadata>
    <dm:org_name><![CDATA[Mimecast Ltd & Co]]></dm:org_name>
    <dm:email>dmarc@mimecast.com</dm:email>
    <dm:report_id>mc-${seq}-${day}</dm:report_id>
    <dm:date_range><dm:begin>${b}</dm:begin><dm:end>${b + 86399}</dm:end></dm:date_range>
  </dm:report_metadata>
  <dm:policy_published><dm:domain>${DOMAIN}</dm:domain><dm:adkim>r</dm:adkim><dm:aspf>r</dm:aspf><dm:p>quarantine</dm:p><dm:sp>quarantine</dm:sp><dm:pct>100</dm:pct></dm:policy_published>
${rows}
</dm:feedback>
`;
}

/** Fastmail-style: numeric entity in org name, <reason> blocks, no <sp>. */
function emitFastmail(day: string, records: GenRecord[], seq: number): string {
  const b = dayToEpoch(day);
  const rows = records
    .map(
      (r) => `  <record>
    <row>
      <source_ip>${r.ip}</source_ip>
      <count>${r.count}</count>
      <policy_evaluated>
        <disposition>${r.disposition}</disposition>
        <dkim>${r.dkimEval}</dkim>
        <spf>${r.spfEval}</spf>
${r.disposition !== 'none' ? '        <reason><type>local_policy</type><comment>failed dmarc, applied domain policy</comment></reason>' : ''}
      </policy_evaluated>
    </row>
    <identifiers><header_from>${r.headerFrom}</header_from></identifiers>
    <auth_results>
${r.dkim.map((d) => `      <dkim><domain>${d.domain}</domain><selector>${d.selector ?? 'fm1'}</selector><result>${d.result}</result></dkim>`).join('\n')}
${r.spf.map((s) => `      <spf><domain>${s.domain}</domain><scope>mfrom</scope><result>${s.result}</result></spf>`).join('\n')}
    </auth_results>
  </record>`,
    )
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE feedback SYSTEM "rua.dtd">
<feedback>
  <report_metadata>
    <org_name>Fastmail Pty Ltd &#40;DMARC&#41;</org_name>
    <email>dmarc&#64;fastmail.com</email>
    <report_id>fm${seq}${day.replace(/-/g, '')}</report_id>
    <date_range><begin>${b}</begin><end>${b + 86399}</end></date_range>
  </report_metadata>
  <policy_published><domain>${esc(DOMAIN)}</domain><adkim>r</adkim><aspf>r</aspf><p>quarantine</p></policy_published>
${rows}
</feedback>
`;
}

const EMITTERS: Record<ProviderName, (day: string, r: GenRecord[], seq: number) => string> = {
  google: emitGoogle,
  microsoft: emitMicrosoft,
  yahoo: emitYahoo,
  mimecast: emitMimecast,
  fastmail: emitFastmail,
};

// --- the scenario itself ---------------------------------------------------

export type PlantedTruth = {
  domain: string;
  marketingSubdomain: string;
  claimsSubdomain: string;
  surveySubdomain: string;
  breakDay: string;
  days: string[];
  trueOpenRate: number;
  brokenShareAfter: number;
  espIp: string;
  spoofIp: string;
  newVendorIp: string;
  dkimBrokenIp: string;
  forwarderIps: string[];
  authorisedIps: string[];
};

export type Corpus = {
  /** Raw RUA XML documents, exactly as a provider would mail them. */
  xml: string[];
  /** Opens the ESP logged for the marketing stream, per day. */
  engagement: EngagementDay[];
  truth: PlantedTruth;
};

function dayRecords(day: string, dayIndex: number, rnd: () => number): GenRecord[] {
  const broken = day >= BREAK_DAY;
  const out: GenRecord[] = [];

  // Marketing stream, SPF-only (the ESP never set up DKIM for this subdomain).
  const marketingVolume = 12000 + Math.round(gaussian(rnd) * 350);
  if (broken) {
    const bad = Math.round(marketingVolume * BROKEN_SHARE_AFTER);
    out.push({
      ip: ESP_IP,
      count: bad,
      disposition: 'quarantine',
      dkimEval: 'fail',
      spfEval: 'fail',
      headerFrom: MARKETING_SUBDOMAIN,
      envelopeFrom: 'bounce.acme-esp.net',
      dkim: [],
      // F1: SPF still PASSES - for the WRONG domain. Alignment, not authorisation.
      spf: [{ domain: 'bounce.acme-esp.net', result: 'pass' }],
    });
    out.push({
      ip: ESP_IP,
      count: marketingVolume - bad,
      disposition: 'none',
      dkimEval: 'fail',
      spfEval: 'pass',
      headerFrom: MARKETING_SUBDOMAIN,
      envelopeFrom: `bounce.${DOMAIN}`,
      dkim: [],
      spf: [{ domain: `bounce.${DOMAIN}`, result: 'pass' }],
    });
  } else {
    out.push({
      ip: ESP_IP,
      count: marketingVolume,
      disposition: 'none',
      dkimEval: 'fail',
      spfEval: 'pass',
      headerFrom: MARKETING_SUBDOMAIN,
      envelopeFrom: `bounce.${DOMAIN}`,
      dkim: [],
      spf: [{ domain: `bounce.${DOMAIN}`, result: 'pass' }],
    });
  }

  // Corporate / transactional: fully authenticated throughout.
  out.push({
    ip: CORP_IP,
    count: 2600 + Math.round(gaussian(rnd) * 90),
    disposition: 'none',
    dkimEval: 'pass',
    spfEval: 'pass',
    headerFrom: DOMAIN,
    envelopeFrom: DOMAIN,
    dkim: [{ domain: DOMAIN, selector: 'corp2026', result: 'pass' }],
    spf: [{ domain: DOMAIN, result: 'pass' }],
  });

  // F4: DKIM broke at a key rotation, SPF still aligns -> DMARC PASSES -> delivered.
  out.push({
    ip: CLAIMS_IP,
    count: 1800 + Math.round(gaussian(rnd) * 70),
    disposition: 'none',
    dkimEval: 'fail',
    spfEval: 'pass',
    headerFrom: CLAIMS_SUBDOMAIN,
    envelopeFrom: CLAIMS_SUBDOMAIN,
    dkim: [{ domain: CLAIMS_SUBDOMAIN, selector: 'claims-rot7', result: 'fail' }],
    spf: [{ domain: CLAIMS_SUBDOMAIN, result: 'pass' }],
  });

  // F3: unfamiliar IP, but it holds an aligned DKIM key -> a new vendor.
  out.push({
    ip: NEW_VENDOR_IP,
    count: 340 + Math.round(gaussian(rnd) * 25),
    disposition: 'none',
    dkimEval: 'pass',
    spfEval: 'fail',
    headerFrom: SURVEY_SUBDOMAIN,
    envelopeFrom: 'bounces.surveyvendor.io',
    dkim: [{ domain: SURVEY_SUBDOMAIN, selector: 'sv1', result: 'pass' }],
    spf: [{ domain: 'bounces.surveyvendor.io', result: 'pass' }],
  });

  // F2: never-authorised third party sending as the root domain, at volume.
  out.push({
    ip: SPOOF_IP,
    count: 900 + Math.round(Math.abs(gaussian(rnd)) * 220),
    disposition: 'quarantine',
    dkimEval: 'fail',
    spfEval: 'fail',
    headerFrom: DOMAIN,
    envelopeFrom: DOMAIN,
    dkim: [],
    spf: [{ domain: DOMAIN, result: 'fail' }],
  });

  // F5: forwarding noise. A handful of messages each, unaligned by design.
  for (const ip of FORWARDER_IPS) {
    const n = 1 + Math.floor(rnd() * 9);
    out.push({
      ip,
      count: n,
      disposition: 'quarantine',
      dkimEval: 'fail',
      spfEval: 'fail',
      headerFrom: DOMAIN,
      envelopeFrom: `fwd-${dayIndex}.relay.example.org`,
      dkim: [{ domain: DOMAIN, selector: 'corp2026', result: 'fail' }],
      spf: [{ domain: `relay.example.org`, result: 'pass' }],
    });
  }

  return out;
}

export function generateCorpus(seed = 20260310): Corpus {
  const rnd = mulberry32(seed);
  const xml: string[] = [];
  const engagement: EngagementDay[] = [];
  const days: string[] = [];
  let seq = 1000;

  for (let i = 0; i < DAYS; i++) {
    const day = addDays(START_DAY, i);
    days.push(day);
    const records = dayRecords(day, i, rnd);

    // Opens can only come from mail that was actually delivered. This is the
    // whole point: the generator NEVER produces an open for suppressed volume.
    const deliveredMarketing = records
      .filter((r) => r.headerFrom === MARKETING_SUBDOMAIN && r.disposition === 'none')
      .reduce((a, r) => a + r.count, 0);
    engagement.push({ day, opens: binomial(deliveredMarketing, TRUE_OPEN_RATE, rnd) });

    for (const p of PROVIDERS) {
      const slice = records
        .map((r) => ({ ...r, count: Math.round(r.count * p.share) }))
        .filter((r) => r.count > 0);
      if (slice.length === 0) continue;
      xml.push(EMITTERS[p.name](day, slice, seq++));
    }
  }

  return {
    xml,
    engagement,
    truth: {
      domain: DOMAIN,
      marketingSubdomain: MARKETING_SUBDOMAIN,
      claimsSubdomain: CLAIMS_SUBDOMAIN,
      surveySubdomain: SURVEY_SUBDOMAIN,
      breakDay: BREAK_DAY,
      days,
      trueOpenRate: TRUE_OPEN_RATE,
      brokenShareAfter: BROKEN_SHARE_AFTER,
      espIp: ESP_IP,
      spoofIp: SPOOF_IP,
      newVendorIp: NEW_VENDOR_IP,
      dkimBrokenIp: CLAIMS_IP,
      forwarderIps: FORWARDER_IPS,
      authorisedIps: AUTHORISED_IPS,
    },
  };
}
