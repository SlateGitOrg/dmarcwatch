/**
 * DMARC aggregate (RUA) report model + a tolerant reader over the parsed XML.
 *
 * The RFC 7489 Appendix C schema is small, but no two reporting providers emit
 * the same subset of it. The variance this reader is built to absorb, all of it
 * observed in real feeds:
 *
 *  - Element ORDER. `<record>` may hold `<row>` then `<identifiers>` then
 *    `<auth_results>`, or any permutation. We look children up by name, never
 *    by position.
 *  - Optional elements simply absent: `<extra_contact_info>`, `<selector>`,
 *    `<scope>`, `<pct>`, `<sp>`, `<envelope_to>`.
 *  - Result CASE. Microsoft emits `Pass`/`Fail`; Google emits lowercase.
 *  - Namespace prefixes on every element (some gateway vendors).
 *  - CDATA and numeric character references inside `<org_name>`.
 *  - REPEATED `<dkim>` blocks in `<auth_results>` (multi-signature mail).
 *
 * Design choice: malformed *records* are collected as warnings and dropped, not
 * thrown. One bad record in a 4000-record Google report must not cost you the
 * whole day's visibility. Malformed *documents* still throw, because a report
 * you cannot open is a fact the operator needs to see.
 */

import { kid, kids, parseXml, textAt, type XmlNode } from './xml.ts';

export type Disposition = 'none' | 'quarantine' | 'reject';
export type DmarcEval = 'pass' | 'fail';

export type AuthDkim = { domain: string; selector?: string; result: string };
export type AuthSpf = { domain: string; scope?: string; result: string };

export type DmarcRecord = {
  sourceIp: string;
  count: number;
  disposition: Disposition;
  /** policy_evaluated/dkim: DKIM *aligned and passing*, not raw DKIM validity. */
  dkimEvaluated: DmarcEval;
  spfEvaluated: DmarcEval;
  reasons: { type: string; comment?: string }[];
  headerFrom: string;
  envelopeFrom?: string;
  envelopeTo?: string;
  dkimAuth: AuthDkim[];
  spfAuth: AuthSpf[];
};

export type PolicyPublished = {
  domain: string;
  adkim: 'r' | 's';
  aspf: 'r' | 's';
  p: Disposition;
  sp?: Disposition;
  pct: number;
  fo?: string;
};

export type ReportMetadata = {
  orgName: string;
  email?: string;
  extraContactInfo?: string;
  reportId: string;
  /** Unix seconds. */
  begin: number;
  end: number;
  errors: string[];
};

export type AggregateReport = {
  metadata: ReportMetadata;
  policy: PolicyPublished;
  records: DmarcRecord[];
  /** Non-fatal problems: dropped records, unknown enum values, absent fields. */
  warnings: string[];
};

export class RuaFormatError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RuaFormatError';
  }
}

function normaliseResult(raw: string | undefined): string | undefined {
  if (raw === undefined) return undefined;
  const t = raw.trim().toLowerCase();
  return t === '' ? undefined : t;
}

function asDisposition(raw: string | undefined, warn: (m: string) => void, where: string): Disposition {
  const t = normaliseResult(raw);
  if (t === undefined) {
    // RFC 7489 makes <disposition> mandatory, but absent means "not acted on".
    return 'none';
  }
  if (t === 'none' || t === 'quarantine' || t === 'reject') return t;
  warn(`${where}: unknown disposition "${raw}" treated as "none"`);
  return 'none';
}

function asEval(raw: string | undefined): DmarcEval {
  // Anything that is not an explicit pass is a fail for DMARC purposes: the
  // policy_evaluated child carries only pass/fail, but providers have shipped
  // "Pass", "PASS" and (rarely) an empty element for unevaluated mail.
  return normaliseResult(raw) === 'pass' ? 'pass' : 'fail';
}

function asAlignment(raw: string | undefined): 'r' | 's' {
  // RFC 7489 6.3: relaxed is the default when the tag is omitted.
  return normaliseResult(raw) === 's' ? 's' : 'r';
}

function asInt(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const t = raw.trim();
  if (!/^-?\d+$/.test(t)) return undefined;
  return Number.parseInt(t, 10);
}

function readRecord(
  node: XmlNode,
  index: number,
  warn: (m: string) => void,
): DmarcRecord | undefined {
  const row = kid(node, 'row');
  const sourceIp = textAt(row, 'source_ip')?.trim();
  const count = asInt(textAt(row, 'count'));
  const identifiers = kid(node, 'identifiers');
  const headerFrom = textAt(identifiers, 'header_from')?.trim().toLowerCase();

  if (sourceIp === undefined || sourceIp === '') {
    warn(`record[${index}]: missing source_ip; record dropped`);
    return undefined;
  }
  if (count === undefined || count < 0) {
    warn(`record[${index}]: missing or non-numeric count; record dropped`);
    return undefined;
  }
  if (headerFrom === undefined || headerFrom === '') {
    // Without header_from there is no alignment question to answer, so the
    // record cannot contribute to any conclusion this tool draws.
    warn(`record[${index}]: missing identifiers/header_from; record dropped`);
    return undefined;
  }

  const evaluated = kid(row, 'policy_evaluated');
  const reasons = kids(evaluated, 'reason').map((r) => {
    const comment = textAt(r, 'comment');
    return {
      type: normaliseResult(textAt(r, 'type')) ?? 'other',
      ...(comment !== undefined && comment !== '' ? { comment } : {}),
    };
  });

  const auth = kid(node, 'auth_results');
  const dkimAuth: AuthDkim[] = [];
  for (const d of kids(auth, 'dkim')) {
    const domain = textAt(d, 'domain')?.trim().toLowerCase();
    const result = normaliseResult(textAt(d, 'result'));
    if (domain === undefined || domain === '' || result === undefined) {
      warn(`record[${index}]: incomplete auth_results/dkim entry ignored`);
      continue;
    }
    const selector = textAt(d, 'selector')?.trim();
    dkimAuth.push({ domain, result, ...(selector ? { selector } : {}) });
  }
  const spfAuth: AuthSpf[] = [];
  for (const s of kids(auth, 'spf')) {
    const domain = textAt(s, 'domain')?.trim().toLowerCase();
    const result = normaliseResult(textAt(s, 'result'));
    if (domain === undefined || domain === '' || result === undefined) {
      warn(`record[${index}]: incomplete auth_results/spf entry ignored`);
      continue;
    }
    const scope = normaliseResult(textAt(s, 'scope'));
    spfAuth.push({ domain, result, ...(scope ? { scope } : {}) });
  }

  const envelopeFrom = textAt(identifiers, 'envelope_from')?.trim().toLowerCase();
  const envelopeTo = textAt(identifiers, 'envelope_to')?.trim().toLowerCase();

  return {
    sourceIp,
    count,
    disposition: asDisposition(textAt(evaluated, 'disposition'), warn, `record[${index}]`),
    dkimEvaluated: asEval(textAt(evaluated, 'dkim')),
    spfEvaluated: asEval(textAt(evaluated, 'spf')),
    reasons,
    headerFrom,
    ...(envelopeFrom ? { envelopeFrom } : {}),
    ...(envelopeTo ? { envelopeTo } : {}),
    dkimAuth,
    spfAuth,
  };
}

export function parseAggregateReport(xml: string): AggregateReport {
  const root = parseXml(xml);
  if (root.name !== 'feedback') {
    throw new RuaFormatError(`expected root element <feedback>, got <${root.name}>`);
  }
  const warnings: string[] = [];
  const warn = (m: string) => warnings.push(m);

  const meta = kid(root, 'report_metadata');
  const range = kid(meta, 'date_range');
  const begin = asInt(textAt(range, 'begin'));
  const end = asInt(textAt(range, 'end'));
  const reportId = textAt(meta, 'report_id')?.trim();
  const orgName = textAt(meta, 'org_name')?.trim();
  if (orgName === undefined || orgName === '') throw new RuaFormatError('report_metadata/org_name is missing');
  if (reportId === undefined || reportId === '') throw new RuaFormatError('report_metadata/report_id is missing');
  if (begin === undefined || end === undefined) {
    throw new RuaFormatError('report_metadata/date_range is missing or non-numeric');
  }
  if (end < begin) {
    // Seen in the wild from one provider that emits <end> before <begin> and
    // occasionally transposes the values too. Order we tolerate silently;
    // transposed values we repair but record, because it shifts every bucket.
    warn(`date_range end (${end}) precedes begin (${begin}); values swapped`);
  }

  const pol = kid(root, 'policy_published');
  const policyDomain = textAt(pol, 'domain')?.trim().toLowerCase();
  if (policyDomain === undefined || policyDomain === '') {
    throw new RuaFormatError('policy_published/domain is missing');
  }
  const pctRaw = asInt(textAt(pol, 'pct'));
  const spRaw = normaliseResult(textAt(pol, 'sp'));
  const fo = normaliseResult(textAt(pol, 'fo'));

  const policy: PolicyPublished = {
    domain: policyDomain,
    adkim: asAlignment(textAt(pol, 'adkim')),
    aspf: asAlignment(textAt(pol, 'aspf')),
    p: asDisposition(textAt(pol, 'p'), warn, 'policy_published'),
    ...(spRaw !== undefined ? { sp: asDisposition(spRaw, warn, 'policy_published/sp') } : {}),
    // RFC 7489: pct defaults to 100 when the tag is absent.
    pct: pctRaw === undefined || pctRaw < 0 || pctRaw > 100 ? 100 : pctRaw,
    ...(fo !== undefined ? { fo } : {}),
  };

  const records: DmarcRecord[] = [];
  const recordNodes = kids(root, 'record');
  if (recordNodes.length === 0) warn('report contains no <record> elements');
  recordNodes.forEach((r, i) => {
    const parsed = readRecord(r, i, warn);
    if (parsed !== undefined) records.push(parsed);
  });

  return {
    metadata: {
      orgName,
      reportId,
      begin: Math.min(begin, end),
      end: Math.max(begin, end),
      errors: kids(meta, 'error').map((e) => e.text).filter((t) => t !== ''),
      ...(textAt(meta, 'email') ? { email: textAt(meta, 'email')!.trim() } : {}),
      ...(textAt(meta, 'extra_contact_info')
        ? { extraContactInfo: textAt(meta, 'extra_contact_info')!.trim() }
        : {}),
    },
    policy,
    records,
    warnings,
  };
}

/**
 * Organisational domain (eTLD+1) for relaxed alignment.
 *
 * A full public-suffix list is a 15k-line download we are not allowed to ship,
 * so this covers the multi-label suffixes an insurance sender actually uses and
 * falls back to "last two labels". Documented as a limitation rather than
 * hidden: a domain under a suffix outside this table (e.g. `*.s3.amazonaws.com`)
 * would be over-merged, which could make an unrelated sender look aligned.
 */
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'ac.uk', 'gov.uk',
  'com.au', 'net.au', 'org.au', 'co.nz', 'co.za', 'co.jp', 'com.br',
  'com.sg', 'com.mx', 'co.in', 'com.hk',
]);

export function organisationalDomain(domain: string): string {
  const labels = domain.trim().toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length <= 2) return labels.join('.');
  const lastTwo = labels.slice(-2).join('.');
  if (MULTI_LABEL_SUFFIXES.has(lastTwo) && labels.length >= 3) return labels.slice(-3).join('.');
  return lastTwo;
}

/** RFC 7489 3.1: strict alignment is equality; relaxed compares org domains. */
export function isAligned(authDomain: string, headerFrom: string, mode: 'r' | 's'): boolean {
  const a = authDomain.trim().toLowerCase();
  const h = headerFrom.trim().toLowerCase();
  if (mode === 's') return a === h;
  return organisationalDomain(a) === organisationalDomain(h);
}
