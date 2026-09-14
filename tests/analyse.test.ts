import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  attributeChange,
  authHygieneWarnings,
  dailyAuthSeries,
  detectUnauthorisedSenders,
  diagnoseStream,
  findAuthBreak,
  flatten,
  naiveEngagementVerdict,
  splitSeries,
  statsBySource,
  suppressedByDisposition,
  probit,
  type Observation,
  type SplitDay,
} from '../src/analyse.ts';
import { generateCorpus } from '../src/fixtures.ts';
import { parseAggregateReport } from '../src/rua.ts';

const corpus = generateCorpus();
const truth = corpus.truth;
const observations: Observation[] = flatten(corpus.xml.map(parseAggregateReport));
const marketing = observations.filter((o) => o.record.headerFrom === truth.marketingSubdomain);
const split = splitSeries(marketing, corpus.engagement);
const baseline = split.filter((d) => d.day < truth.breakDay);
const current = split.filter((d) => d.day >= truth.breakDay);

const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0);
const delivered = (w: SplitDay[]) => sum(w.map((d) => d.delivered));

/**
 * Standard error of a difference in two open rates measured on the delivered
 * volumes of the two windows. Every tolerance below is built from this, not
 * from a round number that looked reasonable.
 */
function seOfDifference(p: number, n1: number, n2: number): number {
  return Math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2));
}

describe('the split: deliverability failure vs engagement failure', () => {
  it('the naive open-rate view blames the audience', () => {
    // The baseline this project exists to beat. If this assertion ever stops
    // holding, the scenario has stopped being the one the README describes.
    const naive = naiveEngagementVerdict(baseline, current);
    assert.ok(naive.openRateChange < -0.15, `naive change ${naive.openRateChange}`);
    assert.match(naive.conclusion, /fatigue|subject-line/);
  });

  it('recovers the planted true open rate, which never moved', () => {
    const attr = attributeChange(baseline, current);
    const se = seOfDifference(truth.trueOpenRate, delivered(baseline), delivered(current));
    // 3 SE two-sided: under the planted null (engagement unchanged) this fails
    // about 0.3% of the time, and the corpus is seeded so it is deterministic.
    assert.ok(
      Math.abs(attr.currentTrue - attr.baselineTrue) < 3 * se,
      `true open rate moved ${(attr.currentTrue - attr.baselineTrue).toFixed(5)} vs 3se=${(3 * se).toFixed(5)}`,
    );
    assert.ok(Math.abs(attr.baselineTrue - truth.trueOpenRate) < 3 * se);
    assert.ok(Math.abs(attr.currentTrue - truth.trueOpenRate) < 3 * se);
  });

  it('the generic fix - counting quarantined mail as delivered - does NOT recover it', () => {
    // This is the same computation with the one decision removed: treat every
    // message the provider reported as "sent" as though it had arrived. If the
    // differentiator were implemented the obvious way, this is the answer it
    // would give, and it is wrong by ~70 standard errors.
    const genericCurrentRate = sum(current.map((d) => d.opens)) / sum(current.map((d) => d.sent));
    const se = seOfDifference(truth.trueOpenRate, delivered(baseline), delivered(current));
    assert.ok(
      Math.abs(genericCurrentRate - truth.trueOpenRate) > 20 * se,
      `generic rate ${genericCurrentRate} is not far enough from the truth to make the point`,
    );
    assert.ok(genericCurrentRate < truth.trueOpenRate / 2);
  });

  it('attributes the move exactly, with no residual to hide a judgement in', () => {
    const attr = attributeChange(baseline, current);
    // The Shapley split is an identity: the two components must reconstruct the
    // observed change to floating-point precision.
    assert.ok(
      Math.abs(attr.deliverabilityPoints + attr.engagementPoints - attr.naiveChange) < 1e-12,
      'components do not sum to the observed change',
    );
    assert.equal(attr.verdict, 'deliverability');

    const se = seOfDifference(truth.trueOpenRate, delivered(baseline), delivered(current));
    assert.ok(Math.abs(attr.engagementPoints) < 3 * se, `engagement component ${attr.engagementPoints}`);
    assert.ok(
      Math.abs(attr.deliverabilityPoints) / Math.abs(attr.naiveChange) > 0.95,
      'deliverability should account for essentially all of the decline',
    );
  });

  it('counts the volume whose engagement is structurally missing, not low', () => {
    const attr = attributeChange(baseline, current);
    const disp = suppressedByDisposition(marketing.filter((o) => o.day >= truth.breakDay));
    assert.equal(attr.structurallyMissing, disp.quarantined + disp.rejected);
    // The planted fault moves BROKEN_SHARE_AFTER of the stream; anything much
    // off that means the suppression accounting has drifted.
    const sentCurrent = sum(current.map((d) => d.sent));
    assert.ok(Math.abs(attr.structurallyMissing / sentCurrent - truth.brokenShareAfter) < 0.01);
    // And no open was ever attributed to suppressed volume.
    for (const d of current) assert.ok(d.opens <= d.delivered);
  });

  it('reports no material change when nothing broke', () => {
    // Negative control: baseline against itself split in half must not produce
    // a verdict. A detector that always finds something is not a detector.
    const half = Math.floor(baseline.length / 2);
    const attr = attributeChange(baseline.slice(0, half), baseline.slice(half));
    assert.equal(attr.verdict, 'no-material-change');
    // ...and it must still detect a real engagement drop of the same scale as
    // the incident when delivery is untouched (the detector is not just mute).
    const dropped = baseline.slice(half).map((d) => ({ ...d, opens: Math.round(d.opens * 0.8) }));
    assert.equal(attributeChange(baseline.slice(0, half), dropped).verdict, 'engagement');
  });
});

describe('the authentication break', () => {
  it('finds the planted break day and calls it significant', () => {
    const brk = findAuthBreak(dailyAuthSeries(marketing))!;
    assert.ok(brk !== undefined);
    assert.equal(brk.day, truth.breakDay);
    assert.equal(brk.significant, true);
    assert.ok(brk.beforeRate > 0.99);
    assert.ok(Math.abs(brk.afterRate - (1 - truth.brokenShareAfter)) < 0.01);
  });

  it('finds no significant break in a stream that never broke', () => {
    const corp = observations.filter((o) => o.record.headerFrom === truth.domain && o.record.sourceIp === '198.51.100.20');
    const brk = findAuthBreak(dailyAuthSeries(corp));
    assert.ok(brk === undefined || brk.significant === false, JSON.stringify(brk));
  });

  it('names the root cause, not merely the failure', () => {
    const causes = diagnoseStream(marketing);
    const top = causes[0]!;
    // "DMARC failed" is useless; "SPF passes for the wrong domain" is a ticket.
    assert.equal(top.cause, 'spf-alignment');
    assert.match(top.example, /bounce\.acme-esp\.net/);
    assert.match(top.example, /relaxed aspf/);
    // The stream is SPF-only, so the absence of DKIM is the reason a single
    // envelope-domain change was able to take the whole stream down.
    assert.ok(causes.some((c) => c.cause === 'dkim-absent'));
    // It is NOT an SPF authorisation problem: the IP is perfectly authorised.
    assert.ok(!causes.some((c) => c.cause === 'spf-authorisation'));
  });

  it('diagnoses the spoofing stream as an authorisation failure instead', () => {
    const spoof = observations.filter((o) => o.record.sourceIp === truth.spoofIp);
    const causes = diagnoseStream(spoof);
    assert.equal(causes[0]!.cause, 'spf-authorisation');
    assert.ok(causes.some((c) => c.cause === 'dkim-absent'));
    assert.ok(!causes.some((c) => c.cause === 'spf-alignment'));
  });
});

describe('a delivering sender with broken DKIM is not a deliverability incident', () => {
  const claims = observations.filter((o) => o.record.headerFrom === truth.claimsSubdomain);

  it('loses no volume at all', () => {
    const disp = suppressedByDisposition(claims);
    assert.equal(disp.quarantined, 0);
    assert.equal(disp.rejected, 0);
    assert.ok(disp.delivered > 40_000);
  });

  it('is reported as hygiene, with the reason it still delivers', () => {
    const w = authHygieneWarnings(observations).find((x) => x.sourceIp === truth.dkimBrokenIp)!;
    assert.ok(w !== undefined);
    assert.match(w.issue, /DKIM signature invalid/);
    assert.match(w.issue, /SPF still aligns/);
  });

  it('would be a false incident for a monitor that charts DKIM pass rate', () => {
    // The generic dashboard's view: DKIM pass rate for this sender is 0%, which
    // looks identical to the real incident. Our split sees 0 suppressed msgs.
    const s = statsBySource(claims).get(truth.dkimBrokenIp)!;
    assert.equal(s.dkimAlignedPass, 0);
    assert.equal(s.dmarcPass, s.volume);
    assert.equal(s.quarantined + s.rejected, 0);
  });
});

describe('unauthorised-sender detection', () => {
  const findings = detectUnauthorisedSenders(observations, { authorisedIps: truth.authorisedIps });
  const byIp = new Map(findings.map((f) => [f.sourceIp, f]));

  it('flags the never-authorised high-volume sender', () => {
    const f = byIp.get(truth.spoofIp)!;
    assert.equal(f.klass, 'suspected-spoofing');
    assert.ok(f.score > probit(1 - 0.05 / findings.length));
  });

  it('does NOT flag an unfamiliar sender that holds an aligned DKIM key', () => {
    // The whole point: a spoofer cannot produce an aligned DKIM pass, so this
    // is an inventory gap (a vendor onboarded without telling the mail team),
    // not an attack - regardless of how unfamiliar the IP is.
    const f = byIp.get(truth.newVendorIp)!;
    assert.equal(f.klass, 'unknown-dkim-authorised');
    assert.match(f.rationale, /inventory gap/);
  });

  it('does NOT flag the forwarding tail', () => {
    for (const ip of truth.forwarderIps) {
      assert.equal(byIp.get(ip)!.klass, 'unflagged-noise', ip);
    }
  });

  it('beats the naive "alert on every unfamiliar IP" rule', () => {
    // The naive detector: anything not in the inventory is suspicious.
    const unfamiliar = [...statsBySource(observations).keys()].filter(
      (ip) => !truth.authorisedIps.includes(ip),
    );
    const naiveFalsePositives = unfamiliar.filter((ip) => ip !== truth.spoofIp).length;
    const ourFalsePositives = findings.filter(
      (f) => f.klass === 'suspected-spoofing' && f.sourceIp !== truth.spoofIp,
    ).length;
    assert.equal(naiveFalsePositives, 6); // 5 forwarders + the new vendor
    assert.equal(ourFalsePositives, 0);
    assert.equal(findings.filter((f) => f.klass === 'suspected-spoofing').length, 1);
  });

  it('refuses to call a lone unfamiliar source spoofing', () => {
    // With no peer group there is no scale to be an outlier against. Flagging
    // here would mean inventing an absolute volume cut-off, which would need
    // re-tuning for every domain size.
    const lone = observations.filter(
      (o) => o.record.sourceIp === truth.spoofIp || truth.authorisedIps.includes(o.record.sourceIp),
    );
    const f = detectUnauthorisedSenders(lone, { authorisedIps: truth.authorisedIps }).find(
      (x) => x.sourceIp === truth.spoofIp,
    )!;
    assert.equal(f.klass, 'unflagged-noise');
    assert.match(f.rationale, /no peer group/);
  });

  it('classifies every authorised source as authorised', () => {
    for (const ip of truth.authorisedIps) assert.equal(byIp.get(ip)!.klass, 'authorised');
  });
});

describe('probit', () => {
  it('matches known quantiles of the standard normal', () => {
    // Acklam's stated bound is RELATIVE error 1.15e-9 (the first version of this
    // test applied it as absolute and failed at p=0.95). The reference values
    // are quoted to 9 decimals, so allow their 5e-10 rounding on top.
    const close = (got: number, want: number) =>
      Math.abs(got - want) <= 1.15e-9 * Math.abs(want) + 5e-10;
    assert.ok(close(probit(0.975), 1.959963985));
    assert.ok(close(probit(0.95), 1.644853627));
    assert.ok(Math.abs(probit(0.5)) < 1e-12);
    assert.ok(close(probit(0.001), -3.090232306));
    // A sign or tail-branch bug would be off by far more than this.
    assert.ok(Math.abs(probit(0.01) + 2.326347874) < 1e-8);
  });
});
