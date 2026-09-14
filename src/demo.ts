/**
 * The 60-second artefact.
 *
 * Reads a month of synthetic RUA XML from five providers and answers the
 * question a marketing team spent two months answering wrongly: did the open
 * rate fall because people stopped caring, or because the mail stopped
 * arriving?
 *
 * ASCII only: the target console is Windows cp1252.
 */

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
  type Observation,
} from './analyse.ts';
import { generateCorpus, GEO } from './fixtures.ts';
import { parseAggregateReport } from './rua.ts';

const n = (v: number) => Math.round(v).toLocaleString('en-US');
const pct = (v: number) => `${(v * 100).toFixed(1)}%`;
const pad = (s: string, w: number) => (s.length >= w ? s : s + ' '.repeat(w - s.length));
const lpad = (s: string, w: number) => (s.length >= w ? s : ' '.repeat(w - s.length) + s);

function rule(width = 78): string {
  return '-'.repeat(width);
}

function head(title: string): void {
  console.log('');
  console.log(`== ${title} ${'='.repeat(Math.max(0, 75 - title.length))}`);
}

function main(): void {
  const corpus = generateCorpus();
  const { truth } = corpus;

  // ---- 1. Ingest ----------------------------------------------------------
  const reports = corpus.xml.map(parseAggregateReport);
  const observations: Observation[] = flatten(reports);
  const providers = [...new Set(reports.map((r) => r.metadata.orgName))];
  const warnings = reports.flatMap((r) => r.warnings);
  const totalVolume = observations.reduce((a, o) => a + o.record.count, 0);

  console.log('dmarcwatch -- deliverability vs engagement from DMARC aggregate reports');
  console.log(rule());
  console.log(`domain            : ${truth.domain}`);
  console.log(`window            : ${truth.days[0]} .. ${truth.days[truth.days.length - 1]} (${truth.days.length} days)`);
  console.log(`RUA documents     : ${reports.length} from ${providers.length} providers`);
  console.log(`providers         : ${providers.join(', ')}`);
  console.log(`records / messages: ${n(observations.length)} rows, ${n(totalVolume)} messages`);
  console.log(`parse warnings    : ${warnings.length}`);

  // ---- 2. Sending sources -------------------------------------------------
  head('Sending sources seen using the domain');
  const findings = detectUnauthorisedSenders(observations, { authorisedIps: truth.authorisedIps });
  const stats = statsBySource(observations);
  console.log(
    `${pad('source IP', 16)}${pad('geo', 14)}${lpad('volume', 9)}${lpad('dmarc ok', 10)}  ${pad('classification', 24)}`,
  );
  console.log(rule());
  for (const f of findings) {
    const s = stats.get(f.sourceIp)!;
    console.log(
      `${pad(f.sourceIp, 16)}${pad(GEO[f.sourceIp] ?? '-', 14)}${lpad(n(s.volume), 9)}` +
        `${lpad(pct(s.volume === 0 ? 0 : s.dmarcPass / s.volume), 10)}  ${pad(f.klass, 24)}`,
    );
  }
  console.log('');
  for (const f of findings) {
    if (f.klass === 'suspected-spoofing' || f.klass === 'unknown-dkim-authorised') {
      console.log(`  [${f.klass}] ${f.sourceIp}`);
      console.log(`      ${f.rationale}`);
    }
  }
  const noise = findings.filter((f) => f.klass === 'unflagged-noise');
  console.log(
    `  [not flagged] ${noise.length} unfamiliar IPs failing alignment at ` +
      `${n(noise.reduce((a, f) => a + f.failingVolume, 0))} msgs total -- forwarding noise, no alert raised.`,
  );

  // ---- 3. The authentication break ---------------------------------------
  head(`Authentication break: ${truth.marketingSubdomain}`);
  const marketing = observations.filter((o) => o.record.headerFrom === truth.marketingSubdomain);
  const series = dailyAuthSeries(marketing);
  const brk = findAuthBreak(series);
  if (brk === undefined) {
    console.log('no changepoint found');
  } else {
    console.log(`changepoint       : ${brk.day}  (planted: ${truth.breakDay})`);
    console.log(`DMARC pass rate   : ${pct(brk.beforeRate)} before -> ${pct(brk.afterRate)} after`);
    console.log(`two-proportion z  : ${brk.zScore.toFixed(1)}   significant: ${brk.significant ? 'YES' : 'no'}`);
  }
  console.log('');
  console.log(`${pad('day', 12)}${lpad('sent', 9)}${lpad('delivered', 11)}${lpad('suppressed', 12)}${lpad('pass rate', 11)}`);
  console.log(rule(55));
  const around = series.filter((d) => Math.abs(dayIndex(d.day, truth.days) - dayIndex(truth.breakDay, truth.days)) <= 3);
  for (const d of around) {
    const mark = d.day === truth.breakDay ? '  <-- break' : '';
    console.log(
      `${pad(d.day, 12)}${lpad(n(d.volume), 9)}${lpad(n(d.delivered), 11)}${lpad(n(d.suppressed), 12)}` +
        `${lpad(pct(d.volume === 0 ? 0 : d.pass / d.volume), 11)}${mark}`,
    );
  }

  // ---- 4. Root cause ------------------------------------------------------
  head('Root cause of the failures (not just "DMARC failed")');
  for (const c of diagnoseStream(marketing)) {
    console.log(`${pad(c.cause, 26)}${lpad(n(c.volume), 10)} msgs`);
    console.log(`  ${c.example}`);
  }

  // ---- 5. THE SPLIT -------------------------------------------------------
  head('Deliverability vs engagement');
  const split = splitSeries(marketing, corpus.engagement);
  const baseline = split.filter((d) => d.day < truth.breakDay);
  const current = split.filter((d) => d.day >= truth.breakDay);
  const naive = naiveEngagementVerdict(baseline, current);
  const attr = attributeChange(baseline, current);

  console.log('NAIVE VIEW (open rate over messages sent) -- what the dashboard shows:');
  console.log(`  open rate ${pct(attr.baselineNaive)} -> ${pct(attr.currentNaive)}  (${(naive.openRateChange * 100).toFixed(1)} points)`);
  console.log(`  conclusion: ${naive.conclusion}`);
  console.log('');
  console.log('DMARC-AWARE VIEW (open rate over messages that actually arrived):');
  console.log(`  true open rate ${pct(attr.baselineTrue)} -> ${pct(attr.currentTrue)}  (planted truth: ${pct(truth.trueOpenRate)}, constant)`);
  console.log(`  messages that could never have been opened: ${n(attr.structurallyMissing)}`);
  console.log('');
  console.log('ATTRIBUTION of the open-rate move (exact, sums to the observed change):');
  console.log(`  deliverability : ${(attr.deliverabilityPoints * 100).toFixed(2)} points`);
  console.log(`  engagement     : ${(attr.engagementPoints * 100).toFixed(2)} points`);
  console.log(`  observed       : ${(attr.naiveChange * 100).toFixed(2)} points`);
  console.log(`  VERDICT        : ${attr.verdict.toUpperCase()}`);
  const disp = suppressedByDisposition(marketing);
  console.log(
    `  disposition of the window: delivered ${n(disp.delivered)}, quarantined ${n(disp.quarantined)}, rejected ${n(disp.rejected)}`,
  );

  // ---- 6. Hygiene ---------------------------------------------------------
  head('Authentication hygiene (delivering fine -- do NOT page anyone)');
  for (const w of authHygieneWarnings(observations).slice(0, 4)) {
    console.log(`${pad(w.headerFrom, 30)}${pad(w.sourceIp, 16)}${lpad(n(w.deliveredVolume), 9)} delivered`);
    console.log(`  ${w.issue}`);
  }
  console.log('');
  console.log(rule());
  console.log(
    `Headline: of the ${(attr.naiveChange * 100).toFixed(2)}-point open-rate decline everyone was ` +
      `A/B-testing, ${(attr.deliverabilityPoints * 100).toFixed(2)} points is mail that never arrived and ` +
      `${(attr.engagementPoints * 100).toFixed(2)} points is how recipients behaved. ` +
      'Engagement among people who received the mail did not move.',
  );
}

function dayIndex(day: string, days: string[]): number {
  return days.indexOf(day);
}

main();
