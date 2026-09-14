/**
 * The analytical layer: what the parsed reports mean.
 *
 * The one idea the whole repo exists for:
 *
 *   Volume that failed DMARC under a quarantine/reject policy DID NOT REACH THE
 *   INBOX. Engagement metrics for that slice are not low, they are STRUCTURALLY
 *   MISSING. An open rate computed over "sent" silently divides real opens by a
 *   denominator that includes mail nobody could ever have opened, and the
 *   resulting decline looks exactly like disinterest.
 *
 * Everything below is in service of splitting an open-rate movement into the
 * part caused by mail not arriving and the part caused by recipients ignoring
 * mail that did arrive.
 */

import {
  isAligned,
  organisationalDomain,
  type AggregateReport,
  type DmarcRecord,
  type PolicyPublished,
} from './rua.ts';

export type Observation = {
  /** UTC date (YYYY-MM-DD) of the report window start. */
  day: string;
  orgName: string;
  policy: PolicyPublished;
  record: DmarcRecord;
};

export function utcDay(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString().slice(0, 10);
}

export function flatten(reports: AggregateReport[]): Observation[] {
  const out: Observation[] = [];
  for (const r of reports) {
    const day = utcDay(r.metadata.begin);
    for (const rec of r.records) {
      out.push({ day, orgName: r.metadata.orgName, policy: r.policy, record: rec });
    }
  }
  return out;
}

/** DMARC passes if EITHER identifier is aligned and passing (RFC 7489 4.2). */
export function dmarcPasses(rec: DmarcRecord): boolean {
  return rec.dkimEvaluated === 'pass' || rec.spfEvaluated === 'pass';
}

/**
 * Did this volume have a chance of being seen?
 *
 * `quarantine` counts as NOT reaching the inbox. That is the judgement call in
 * this file and it is deliberate: quarantined mail lands in a spam folder whose
 * measured open rate is ~0 for bulk insurance mail, so for the purpose of
 * attributing an open-rate movement it behaves like a rejection. The split is
 * reported with quarantine broken out (see `suppressedByDisposition`) so a
 * reader who disagrees can recompute.
 */
export function reachedInbox(rec: DmarcRecord): boolean {
  return rec.disposition === 'none';
}

// ---------------------------------------------------------------------------
// Per-source aggregation
// ---------------------------------------------------------------------------

export type SourceStats = {
  sourceIp: string;
  volume: number;
  dmarcPass: number;
  delivered: number;
  quarantined: number;
  rejected: number;
  /** Volume with an ALIGNED, passing DKIM signature - cryptographic evidence. */
  dkimAlignedPass: number;
  /** Volume with an aligned, passing SPF - evidence of an SPF authorisation. */
  spfAlignedPass: number;
  headerFroms: string[];
  days: string[];
};

export function statsBySource(observations: Observation[]): Map<string, SourceStats> {
  const byIp = new Map<string, SourceStats>();
  for (const o of observations) {
    const rec = o.record;
    let s = byIp.get(rec.sourceIp);
    if (s === undefined) {
      s = {
        sourceIp: rec.sourceIp,
        volume: 0,
        dmarcPass: 0,
        delivered: 0,
        quarantined: 0,
        rejected: 0,
        dkimAlignedPass: 0,
        spfAlignedPass: 0,
        headerFroms: [],
        days: [],
      };
      byIp.set(rec.sourceIp, s);
    }
    s.volume += rec.count;
    if (dmarcPasses(rec)) s.dmarcPass += rec.count;
    if (rec.disposition === 'none') s.delivered += rec.count;
    else if (rec.disposition === 'quarantine') s.quarantined += rec.count;
    else s.rejected += rec.count;
    if (rec.dkimEvaluated === 'pass') s.dkimAlignedPass += rec.count;
    if (rec.spfEvaluated === 'pass') s.spfAlignedPass += rec.count;
    if (!s.headerFroms.includes(rec.headerFrom)) s.headerFroms.push(rec.headerFrom);
    if (!s.days.includes(o.day)) s.days.push(o.day);
  }
  for (const s of byIp.values()) s.days.sort();
  return byIp;
}

// ---------------------------------------------------------------------------
// Unauthorised-sender detection
// ---------------------------------------------------------------------------

export type SenderClass =
  | 'authorised' // in the operator's inventory
  | 'unknown-dkim-authorised' // not in inventory, but holds a valid aligned DKIM key
  | 'unknown-spf-authorised' // not in inventory, but listed in the domain's SPF record
  | 'suspected-spoofing' // no alignment evidence at all, and volume above the noise model
  | 'unflagged-noise'; // no alignment evidence, but indistinguishable from forwarding

export type SenderFinding = {
  sourceIp: string;
  klass: SenderClass;
  volume: number;
  failingVolume: number;
  /** Robust z of log failing volume against the unaligned-source tail; 0 if untested. */
  score: number;
  rationale: string;
};

function median(xs: number[]): number {
  if (xs.length === 0) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 === 1 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2;
}

/**
 * Inverse standard normal CDF (Acklam's rational approximation, |error| < 1.2e-9).
 * Needed to turn a Bonferroni-corrected alpha into a critical z without a stats
 * library.
 */
export function probit(p: number): number {
  if (p <= 0) return -Infinity;
  if (p >= 1) return Infinity;
  const a = [-3.969683028665376e1, 2.209460984245205e2, -2.759285104469687e2, 1.38357751867269e2, -3.066479806614716e1, 2.506628277459239];
  const b = [-5.447609879822406e1, 1.615858368580409e2, -1.556989798598866e2, 6.680131188771972e1, -1.328068155288572e1];
  const c = [-7.784894002430293e-3, -3.223964580411365e-1, -2.400758277161838, -2.549732539343734, 4.374664141464968, 2.938163982698783];
  const d = [7.784695709041462e-3, 3.224671290700398e-1, 2.445134137142996, 3.754408661907416];
  const pLow = 0.02425;
  if (p < pLow) {
    const q = Math.sqrt(-2 * Math.log(p));
    return (((((c[0]! * q + c[1]!) * q + c[2]!) * q + c[3]!) * q + c[4]!) * q + c[5]!) /
      ((((d[0]! * q + d[1]!) * q + d[2]!) * q + d[3]!) * q + 1);
  }
  if (p > 1 - pLow) return -probit(1 - p);
  const q = p - 0.5;
  const r = q * q;
  return ((((((a[0]! * r + a[1]!) * r + a[2]!) * r + a[3]!) * r + a[4]!) * r + a[5]!) * q) /
    (((((b[0]! * r + b[1]!) * r + b[2]!) * r + b[3]!) * r + b[4]!) * r + 1);
}

export type SenderDetectionOptions = {
  /** Source IPs the operator knows about. */
  authorisedIps: Iterable<string>;
  /**
   * Family-wise error rate for the spoofing calls. 0.05 is the conventional
   * FWER; it is split across the tested sources by Bonferroni so that adding
   * more unfamiliar IPs to the corpus does not manufacture detections.
   */
  familywiseAlpha?: number;
  /**
   * Minimum peer group for the outlier test. Below this, a robust scale cannot
   * be estimated and NOTHING is flagged - see the comment on the function.
   */
  minPeerGroup?: number;
};

/**
 * Separate "unfamiliar but legitimate" from "spoofing", without flagging every
 * unfamiliar IP.
 *
 * Rule 1 - ALIGNMENT EVIDENCE IS AUTHORISATION EVIDENCE, and it needs no
 * threshold at all. An aligned, passing DKIM signature means the domain owner
 * handed that sender a private key, which a spoofer cannot forge. An aligned
 * SPF pass means the sender's IP sits inside the domain's own published SPF
 * record. Either way the mail is a gap in the operator's INVENTORY, not an
 * attack, and volume is irrelevant to the call: one aligned DKIM pass is proof.
 *
 * Rule 2 - only sources with ZERO alignment evidence are tested on volume,
 * because benign mail forwarders produce unaligned failures constantly (a
 * forwarded message breaks SPF by construction). Every real domain has a long
 * tail of them, so "fails alignment" cannot be the trigger.
 *
 * The test is a ROBUST OUTLIER test within that tail, not an absolute volume
 * threshold - an absolute number would need re-tuning for every domain size.
 * Failing volumes in the tail are heavy-tailed, so we work in logs and use the
 * median and MAD (scaled by 1.4826, the Gaussian-consistency constant) for
 * location and scale, which one huge spoofing source cannot drag along with it
 * the way a mean and standard deviation would. A source is called spoofing when
 * its robust z exceeds the Bonferroni-corrected one-sided critical value.
 *
 * Deliberate conservatism: with fewer than `minPeerGroup` unaligned unknown
 * sources, or a degenerate (zero) MAD, there is no peer group to be an outlier
 * OF, and the function flags nothing rather than inventing a cut-off.
 */
export function detectUnauthorisedSenders(
  observations: Observation[],
  options: SenderDetectionOptions,
): SenderFinding[] {
  const alpha = options.familywiseAlpha ?? 0.05;
  const minPeers = options.minPeerGroup ?? 4;
  const authorised = new Set(options.authorisedIps);
  const stats = [...statsBySource(observations).values()];

  const findings: SenderFinding[] = [];
  const toTest: SourceStats[] = [];

  for (const s of stats) {
    const failing = s.volume - s.dmarcPass;
    if (authorised.has(s.sourceIp)) {
      findings.push({
        sourceIp: s.sourceIp,
        klass: 'authorised',
        volume: s.volume,
        failingVolume: failing,
        score: 0,
        rationale: 'source is in the authorised-sender inventory',
      });
      continue;
    }
    if (s.dkimAlignedPass > 0) {
      findings.push({
        sourceIp: s.sourceIp,
        klass: 'unknown-dkim-authorised',
        volume: s.volume,
        failingVolume: failing,
        score: 0,
        rationale:
          `${s.dkimAlignedPass.toLocaleString('en-US')} msgs carry an aligned DKIM signature, ` +
          'so a signing key was issued for this sender: inventory gap, not spoofing',
      });
      continue;
    }
    if (s.spfAlignedPass > 0) {
      findings.push({
        sourceIp: s.sourceIp,
        klass: 'unknown-spf-authorised',
        volume: s.volume,
        failingVolume: failing,
        score: 0,
        rationale:
          `${s.spfAlignedPass.toLocaleString('en-US')} msgs pass aligned SPF, so the IP is ` +
          'inside the published SPF record: inventory gap, not spoofing',
      });
      continue;
    }
    toTest.push(s);
  }

  const logs = toTest.map((s) => Math.log(Math.max(1, s.volume - s.dmarcPass)));
  const med = median(logs);
  const mad = median(logs.map((x) => Math.abs(x - med)));
  const scale = 1.4826 * mad;
  const testable = toTest.length >= minPeers && scale > 0;
  const zCrit = testable ? probit(1 - alpha / toTest.length) : Infinity;

  toTest.forEach((s, i) => {
    const failing = s.volume - s.dmarcPass;
    const z = testable ? (logs[i]! - med) / scale : 0;
    const spoof = testable && z > zCrit;
    findings.push({
      sourceIp: s.sourceIp,
      klass: spoof ? 'suspected-spoofing' : 'unflagged-noise',
      volume: s.volume,
      failingVolume: failing,
      score: z,
      rationale: spoof
        ? `no alignment evidence and ${failing.toLocaleString('en-US')} failing msgs: robust ` +
          `z=${z.toFixed(1)} above the unaligned-source tail (median ` +
          `${Math.round(Math.exp(med)).toLocaleString('en-US')} msgs), critical z=${zCrit.toFixed(2)}`
        : testable
          ? `no alignment evidence, but ${failing.toLocaleString('en-US')} failing msgs sits inside ` +
            `the forwarding tail (robust z=${z.toFixed(1)}, critical ${zCrit.toFixed(2)}); not flagged`
          : `no alignment evidence (${failing.toLocaleString('en-US')} failing msgs), but fewer than ` +
            `${minPeers} comparable sources: no peer group to be an outlier of, so not flagged`,
    });
  });

  findings.sort((a, b) => b.volume - a.volume);
  return findings;
}

// ---------------------------------------------------------------------------
// Authentication hygiene (NOT deliverability)
// ---------------------------------------------------------------------------

export type HygieneWarning = {
  sourceIp: string;
  headerFrom: string;
  deliveredVolume: number;
  issue: string;
};

/**
 * Senders whose mail IS being delivered but whose authentication is one change
 * away from breaking - typically DKIM failing while SPF carries the DMARC pass.
 *
 * Kept strictly separate from the deliverability incident list. Reporting a
 * DKIM failure that costs zero delivered messages as an incident is the fastest
 * way to get a real incident ignored, and it is exactly what a dashboard that
 * charts "DKIM pass rate" does by default.
 */
export function authHygieneWarnings(observations: Observation[]): HygieneWarning[] {
  const byKey = new Map<string, HygieneWarning>();
  for (const o of observations) {
    const rec = o.record;
    if (!dmarcPasses(rec) || !reachedInbox(rec)) continue;
    const failedDkim = rec.dkimEvaluated === 'fail';
    const failedSpf = rec.spfEvaluated === 'fail';
    if (!failedDkim && !failedSpf) continue;
    const key = `${rec.sourceIp}|${rec.headerFrom}`;
    const issue = failedDkim
      ? rec.dkimAuth.length === 0
        ? 'no DKIM signature; the DMARC pass rests entirely on SPF, which any forward or relay breaks'
        : `DKIM signature invalid (${rec.dkimAuth.map((d) => d.result).join(', ')}); delivered only because SPF still aligns`
      : 'SPF not aligned; the DMARC pass rests entirely on DKIM';
    const cur = byKey.get(key);
    if (cur === undefined) {
      byKey.set(key, { sourceIp: rec.sourceIp, headerFrom: rec.headerFrom, deliveredVolume: rec.count, issue });
    } else {
      cur.deliveredVolume += rec.count;
    }
  }
  return [...byKey.values()].sort((a, b) => b.deliveredVolume - a.deliveredVolume);
}

// ---------------------------------------------------------------------------
// Alignment-failure diagnosis
// ---------------------------------------------------------------------------

export type RootCause =
  | 'spf-alignment'
  | 'spf-authorisation'
  | 'dkim-alignment'
  | 'dkim-signature-invalid'
  | 'dkim-absent'
  | 'unauthenticated';

export type Diagnosis = { cause: RootCause; volume: number; detail: string };

/**
 * Why did this record fail DMARC? The report already told us THAT it failed;
 * the actionable answer is which of six distinct misconfigurations produced it,
 * because the fix differs in every case (publish an SPF include, re-align the
 * envelope domain, rotate a key, turn signing on).
 */
export function diagnoseRecord(rec: DmarcRecord, policy: PolicyPublished): Diagnosis[] {
  const out: Diagnosis[] = [];
  if (dmarcPasses(rec)) return out;

  for (const spf of rec.spfAuth) {
    if (spf.result === 'pass') {
      if (!isAligned(spf.domain, rec.headerFrom, policy.aspf)) {
        out.push({
          cause: 'spf-alignment',
          volume: rec.count,
          detail:
            `SPF passed for ${spf.domain} but that does not align with header_from ` +
            `${rec.headerFrom} under ${policy.aspf === 's' ? 'strict' : 'relaxed'} aspf ` +
            `(org domains ${organisationalDomain(spf.domain)} vs ${organisationalDomain(rec.headerFrom)})`,
        });
      }
    } else {
      out.push({
        cause: 'spf-authorisation',
        volume: rec.count,
        detail: `SPF result "${spf.result}" for ${spf.domain}: sending IP ${rec.sourceIp} is not authorised by that domain's SPF record`,
      });
    }
  }

  if (rec.dkimAuth.length === 0) {
    out.push({
      cause: 'dkim-absent',
      volume: rec.count,
      detail: `no DKIM signature present on mail from ${rec.sourceIp}; the stream relies on SPF alone`,
    });
  } else {
    for (const d of rec.dkimAuth) {
      if (d.result === 'pass') {
        if (!isAligned(d.domain, rec.headerFrom, policy.adkim)) {
          out.push({
            cause: 'dkim-alignment',
            volume: rec.count,
            detail:
              `DKIM signature by ${d.domain}${d.selector ? ` (selector ${d.selector})` : ''} is valid ` +
              `but misaligned with header_from ${rec.headerFrom} under ` +
              `${policy.adkim === 's' ? 'strict' : 'relaxed'} adkim`,
          });
        }
      } else {
        out.push({
          cause: 'dkim-signature-invalid',
          volume: rec.count,
          detail:
            `DKIM result "${d.result}" for ${d.domain}` +
            `${d.selector ? ` selector ${d.selector}` : ''}: signature did not verify`,
        });
      }
    }
  }

  if (out.length === 0) {
    out.push({
      cause: 'unauthenticated',
      volume: rec.count,
      detail: `mail from ${rec.sourceIp} carried no usable SPF or DKIM evidence at all`,
    });
  }
  return out;
}

export type CauseRollup = { cause: RootCause; volume: number; example: string };

export function diagnoseStream(observations: Observation[]): CauseRollup[] {
  const byCause = new Map<RootCause, CauseRollup>();
  for (const o of observations) {
    for (const d of diagnoseRecord(o.record, o.policy)) {
      const cur = byCause.get(d.cause);
      if (cur === undefined) byCause.set(d.cause, { cause: d.cause, volume: d.volume, example: d.detail });
      else cur.volume += d.volume;
    }
  }
  return [...byCause.values()].sort((a, b) => b.volume - a.volume);
}

// ---------------------------------------------------------------------------
// Changepoint: when did a subdomain's authentication break?
// ---------------------------------------------------------------------------

export type DailyAuth = {
  day: string;
  volume: number;
  pass: number;
  delivered: number;
  suppressed: number;
};

export function dailyAuthSeries(observations: Observation[], headerFrom?: string): DailyAuth[] {
  const byDay = new Map<string, DailyAuth>();
  for (const o of observations) {
    if (headerFrom !== undefined && o.record.headerFrom !== headerFrom) continue;
    let d = byDay.get(o.day);
    if (d === undefined) {
      d = { day: o.day, volume: 0, pass: 0, delivered: 0, suppressed: 0 };
      byDay.set(o.day, d);
    }
    d.volume += o.record.count;
    if (dmarcPasses(o.record)) d.pass += o.record.count;
    if (reachedInbox(o.record)) d.delivered += o.record.count;
    else d.suppressed += o.record.count;
  }
  return [...byDay.values()].sort((a, b) => a.day.localeCompare(b.day));
}

export type Changepoint = {
  day: string;
  zScore: number;
  pValue: number;
  beforeRate: number;
  afterRate: number;
  significant: boolean;
};

/** Two-sided normal tail, via an Abramowitz-Stegun 7.1.26 erf approximation. */
function normalTwoSided(z: number): number {
  const x = Math.abs(z) / Math.SQRT2;
  const t = 1 / (1 + 0.3275911 * x);
  const y =
    1 -
    ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592) *
      t *
      Math.exp(-x * x);
  return Math.max(0, Math.min(1, 1 - y));
}

/**
 * Find the day a pass rate broke.
 *
 * Scans every split point with a two-proportion z-test and keeps the strongest.
 * The significance bar is Bonferroni-corrected across the candidate split
 * points that were actually scanned - without that correction, searching ~30
 * days for the biggest jump finds a "significant" break in stationary noise
 * about 80% of the time.
 */
export function findAuthBreak(series: DailyAuth[], alpha = 0.05): Changepoint | undefined {
  if (series.length < 4) return undefined;
  const candidates = series.length - 3; // need >= 2 days either side
  if (candidates <= 0) return undefined;
  let best: Changepoint | undefined;

  for (let split = 2; split <= series.length - 2; split++) {
    const before = series.slice(0, split);
    const after = series.slice(split);
    const n1 = before.reduce((a, d) => a + d.volume, 0);
    const x1 = before.reduce((a, d) => a + d.pass, 0);
    const n2 = after.reduce((a, d) => a + d.volume, 0);
    const x2 = after.reduce((a, d) => a + d.pass, 0);
    if (n1 === 0 || n2 === 0) continue;
    const p1 = x1 / n1;
    const p2 = x2 / n2;
    const pooled = (x1 + x2) / (n1 + n2);
    const se = Math.sqrt(pooled * (1 - pooled) * (1 / n1 + 1 / n2));
    if (se === 0) continue;
    const z = (p1 - p2) / se;
    if (best === undefined || Math.abs(z) > Math.abs(best.zScore)) {
      best = {
        day: series[split]!.day,
        zScore: z,
        pValue: normalTwoSided(z),
        beforeRate: p1,
        afterRate: p2,
        significant: false,
      };
    }
  }
  if (best === undefined) return undefined;
  best.significant = best.pValue < alpha / candidates;
  return best;
}

// ---------------------------------------------------------------------------
// THE SPLIT: deliverability vs engagement
// ---------------------------------------------------------------------------

/** Opens the ESP recorded, per day. Opens can only ever come from DELIVERED mail. */
export type EngagementDay = { day: string; opens: number };

export type SplitDay = {
  day: string;
  sent: number;
  delivered: number;
  suppressed: number;
  opens: number;
  /** opens / sent - what the marketing dashboard shows. */
  naiveOpenRate: number;
  /** opens / delivered - the rate among people who could actually open it. */
  trueOpenRate: number;
  deliveryRate: number;
};

export function splitSeries(
  observations: Observation[],
  engagement: EngagementDay[],
  headerFrom?: string,
): SplitDay[] {
  const opensByDay = new Map(engagement.map((e) => [e.day, e.opens]));
  return dailyAuthSeries(observations, headerFrom).map((d) => {
    const opens = opensByDay.get(d.day) ?? 0;
    return {
      day: d.day,
      sent: d.volume,
      delivered: d.delivered,
      suppressed: d.suppressed,
      opens,
      naiveOpenRate: d.volume === 0 ? 0 : opens / d.volume,
      trueOpenRate: d.delivered === 0 ? 0 : opens / d.delivered,
      deliveryRate: d.volume === 0 ? 0 : d.delivered / d.volume,
    };
  });
}

export type Attribution = {
  baselineNaive: number;
  currentNaive: number;
  naiveChange: number;
  baselineTrue: number;
  currentTrue: number;
  /** Points of the naive change caused by mail not arriving. */
  deliverabilityPoints: number;
  /** Points caused by recipients who received it behaving differently. */
  engagementPoints: number;
  /** Volume that could not have been opened by anyone, in the current window. */
  structurallyMissing: number;
  verdict: 'deliverability' | 'engagement' | 'mixed' | 'no-material-change';
};

/**
 * Decompose a movement in the naive open rate.
 *
 * naive = deliveryRate * trueOpenRate, so the change factors EXACTLY as
 *
 *   d1*t1 - d0*t0 = tbar*(d1-d0) + dbar*(t1-t0),  tbar=(t0+t1)/2, dbar=(d0+d1)/2
 *
 * This is the symmetric (Shapley) split of the interaction term - it is an
 * identity, not an approximation, so the two components always sum to the
 * observed change and there is no residual to hide a judgement call in.
 */
export function attributeChange(
  baseline: SplitDay[],
  current: SplitDay[],
  /**
   * How large a component must be to be named the cause, in open-rate points.
   * Default is the pooled binomial standard error of the baseline true open
   * rate: a component smaller than the sampling noise of the measurement that
   * produced it is not a finding.
   */
  materialityPoints?: number,
): Attribution {
  const agg = (w: SplitDay[]) => {
    const sent = w.reduce((a, d) => a + d.sent, 0);
    const delivered = w.reduce((a, d) => a + d.delivered, 0);
    const opens = w.reduce((a, d) => a + d.opens, 0);
    return {
      sent,
      delivered,
      opens,
      d: sent === 0 ? 0 : delivered / sent,
      t: delivered === 0 ? 0 : opens / delivered,
      naive: sent === 0 ? 0 : opens / sent,
    };
  };
  const b = agg(baseline);
  const c = agg(current);
  const dbar = (b.d + c.d) / 2;
  const tbar = (b.t + c.t) / 2;
  const deliverabilityPoints = tbar * (c.d - b.d);
  const engagementPoints = dbar * (c.t - b.t);

  // Each component is a scaled DIFFERENCE of two binomial proportions, so its
  // noise is the SE of that difference (pooled rate, both windows' sizes), not
  // the SE of the baseline rate alone. An earlier version used the baseline-only
  // SE, which is ~sqrt(2) too narrow; the negative-control test caught it calling
  // a z=-1.56 stationary wobble an "engagement" finding. 1.96 = two-sided 5%.
  const Z = 1.96;
  const seDiff = (x0: number, n0: number, x1: number, n1: number) => {
    if (n0 === 0 || n1 === 0) return 0;
    const p = (x0 + x1) / (n0 + n1);
    return Math.sqrt(p * (1 - p) * (1 / n0 + 1 / n1));
  };
  const dBar = materialityPoints ?? Z * tbar * seDiff(b.delivered, b.sent, c.delivered, c.sent);
  const eBar = materialityPoints ?? Z * dbar * seDiff(b.opens, b.delivered, c.opens, c.delivered);

  const dMat = Math.abs(deliverabilityPoints) > dBar;
  const eMat = Math.abs(engagementPoints) > eBar;
  const verdict: Attribution['verdict'] =
    dMat && eMat ? 'mixed' : dMat ? 'deliverability' : eMat ? 'engagement' : 'no-material-change';

  return {
    baselineNaive: b.naive,
    currentNaive: c.naive,
    naiveChange: c.naive - b.naive,
    baselineTrue: b.t,
    currentTrue: c.t,
    deliverabilityPoints,
    engagementPoints,
    structurallyMissing: c.sent - c.delivered,
    verdict,
  };
}

/**
 * The naive reading: "opens fell, recipients lost interest."
 *
 * Implemented explicitly so the test suite can assert what the obvious
 * alternative concludes, rather than asserting only that our answer is right.
 */
export function naiveEngagementVerdict(
  baseline: SplitDay[],
  current: SplitDay[],
): { openRateChange: number; conclusion: string } {
  const rate = (w: SplitDay[]) => {
    const sent = w.reduce((a, d) => a + d.sent, 0);
    const opens = w.reduce((a, d) => a + d.opens, 0);
    return sent === 0 ? 0 : opens / sent;
  };
  const change = rate(current) - rate(baseline);
  return {
    openRateChange: change,
    conclusion:
      change < 0
        ? 'open rate declined: audience fatigue / subject-line problem - run creative tests'
        : 'open rate stable or improving',
  };
}

export function suppressedByDisposition(observations: Observation[]): {
  delivered: number;
  quarantined: number;
  rejected: number;
} {
  let delivered = 0;
  let quarantined = 0;
  let rejected = 0;
  for (const o of observations) {
    if (o.record.disposition === 'none') delivered += o.record.count;
    else if (o.record.disposition === 'quarantine') quarantined += o.record.count;
    else rejected += o.record.count;
  }
  return { delivered, quarantined, rejected };
}
