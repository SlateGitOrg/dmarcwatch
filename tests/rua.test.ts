import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { generateCorpus } from '../src/fixtures.ts';
import {
  isAligned,
  organisationalDomain,
  parseAggregateReport,
  RuaFormatError,
} from '../src/rua.ts';

const corpus = generateCorpus();
const reports = corpus.xml.map(parseAggregateReport);

describe('RUA ingestion across provider dialects', () => {
  it('reads all five dialects and agrees on the same facts', () => {
    const orgs = new Set(reports.map((r) => r.metadata.orgName));
    assert.equal(orgs.size, 5, [...orgs].join(' | '));

    // Every dialect must yield the same policy domain and the same alignment
    // modes, despite Microsoft omitting <adkim>/<aspf>/<pct> entirely and
    // Fastmail omitting <sp>. Defaults come from RFC 7489, not from guesswork.
    for (const r of reports) {
      assert.equal(r.policy.domain, 'insurer-example.com');
      assert.equal(r.policy.adkim, 'r');
      assert.equal(r.policy.aspf, 'r');
      assert.equal(r.policy.pct, 100);
      assert.equal(r.policy.p, 'quarantine');
      assert.ok(r.records.length > 0);
      assert.equal(r.warnings.length, 0, r.warnings.join('; '));
    }
  });

  it('recovers identical volume from every provider for the same sender', () => {
    // The dialects differ in case, ordering, nesting and namespace prefix. If
    // any of that leaked into the reader, per-provider totals for one source
    // would diverge from its share of the day's send.
    const perProvider = new Map<string, number>();
    for (const r of reports) {
      const v = r.records
        .filter((rec) => rec.sourceIp === '198.51.100.20')
        .reduce((a, rec) => a + rec.count, 0);
      perProvider.set(r.metadata.orgName, (perProvider.get(r.metadata.orgName) ?? 0) + v);
    }
    // Shares are 0.42 / 0.28 / 0.14 / 0.09 / 0.07; the ratio google:yahoo is 3.
    const google = perProvider.get('google.com')!;
    const yahoo = perProvider.get('Yahoo')!;
    assert.ok(google > 0 && yahoo > 0);
    // Rounding per day, 29 days: |error| is at most 29 * 0.5 messages on each side.
    const maxRoundingError = 29 * 0.5 * (1 + 3);
    assert.ok(Math.abs(google - 3 * yahoo) <= maxRoundingError, `${google} vs 3*${yahoo}`);
  });

  it('normalises Title-Case results and absent optional elements', () => {
    const ms = reports.find((r) => r.metadata.orgName === 'Enterprise Outlook')!;
    const corp = ms.records.find((r) => r.sourceIp === '198.51.100.20')!;
    assert.equal(corp.dkimEvaluated, 'pass'); // emitted as "Pass"
    assert.equal(corp.spfEvaluated, 'pass');
    assert.equal(corp.dkimAuth[0]!.result, 'pass');
    assert.equal(corp.dkimAuth[0]!.selector, undefined); // Microsoft omits it
    assert.equal(corp.envelopeTo, 'contoso.com');
    assert.equal(ms.metadata.extraContactInfo, undefined);

    const google = reports.find((r) => r.metadata.orgName === 'google.com')!;
    assert.equal(google.records.find((r) => r.sourceIp === '198.51.100.20')!.dkimAuth[0]!.selector, 'corp2026');
    assert.ok(google.metadata.extraContactInfo!.startsWith('https://'));
  });

  it('repairs a transposed date_range and keeps the window one day wide', () => {
    const yahoo = reports.find((r) => r.metadata.orgName === 'Yahoo')!;
    assert.ok(yahoo.metadata.end > yahoo.metadata.begin);
    assert.equal(yahoo.metadata.end - yahoo.metadata.begin, 86399);
  });

  it('keeps multiple DKIM signatures rather than the first one only', () => {
    const mc = reports.find((r) => r.metadata.orgName.startsWith('Mimecast'))!;
    const signed = mc.records.find((r) => r.dkimAuth.length > 0)!;
    assert.equal(signed.dkimAuth.length, 2);
    assert.ok(signed.dkimAuth.some((d) => d.domain === 'mimecast-relay.net'));
    // CDATA-wrapped org name with an ampersand survives intact.
    assert.equal(mc.metadata.orgName, 'Mimecast Ltd & Co');
  });

  it('decodes numeric character references in metadata', () => {
    const fm = reports.find((r) => r.metadata.orgName.startsWith('Fastmail'))!;
    assert.equal(fm.metadata.orgName, 'Fastmail Pty Ltd (DMARC)');
    assert.equal(fm.metadata.email, 'dmarc@fastmail.com');
    // Fastmail omits <sp>; it must be absent, not silently defaulted to <p>.
    assert.equal(fm.policy.sp, undefined);
  });

  it('carries the policy_evaluated <reason> through', () => {
    const fm = reports.find((r) => r.metadata.orgName.startsWith('Fastmail'))!;
    const suppressed = fm.records.find((r) => r.disposition === 'quarantine')!;
    assert.equal(suppressed.reasons[0]!.type, 'local_policy');
    assert.match(suppressed.reasons[0]!.comment!, /applied domain policy/);
  });
});

describe('malformed input', () => {
  const wrap = (records: string) => `<feedback>
    <report_metadata><org_name>test</org_name><report_id>r1</report_id>
      <date_range><begin>1772928000</begin><end>1773014399</end></date_range></report_metadata>
    <policy_published><domain>example.com</domain><p>none</p></policy_published>
    ${records}</feedback>`;

  it('drops an unusable record with a warning instead of losing the report', () => {
    // A single bad row in a 4000-row Google report must not cost a day of
    // visibility; it must also not silently vanish.
    const r = parseAggregateReport(
      wrap(`
      <record><row><source_ip>1.2.3.4</source_ip><count>10</count>
        <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
        <identifiers><header_from>example.com</header_from></identifiers></record>
      <record><row><count>50</count></row><identifiers><header_from>example.com</header_from></identifiers></record>
      <record><row><source_ip>5.6.7.8</source_ip><count>not-a-number</count></row>
        <identifiers><header_from>example.com</header_from></identifiers></record>
      <record><row><source_ip>9.9.9.9</source_ip><count>3</count></row></record>`),
    );
    assert.equal(r.records.length, 1);
    assert.equal(r.records[0]!.count, 10);
    assert.equal(r.warnings.length, 3);
    assert.match(r.warnings[0]!, /missing source_ip/);
    assert.match(r.warnings[1]!, /non-numeric count/);
    assert.match(r.warnings[2]!, /header_from/);
  });

  it('treats an unknown disposition as "none" and says so', () => {
    const r = parseAggregateReport(
      wrap(`<record><row><source_ip>1.2.3.4</source_ip><count>10</count>
        <policy_evaluated><disposition>sandbox</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
        <identifiers><header_from>example.com</header_from></identifiers></record>`),
    );
    assert.equal(r.records[0]!.disposition, 'none');
    assert.match(r.warnings.join(), /unknown disposition "sandbox"/);
  });

  it('throws on a document whose identity cannot be established', () => {
    assert.throws(() => parseAggregateReport('<report><a/></report>'), RuaFormatError);
    assert.throws(
      () =>
        parseAggregateReport(
          '<feedback><report_metadata><report_id>x</report_id></report_metadata></feedback>',
        ),
      /org_name is missing/,
    );
    assert.throws(
      () =>
        parseAggregateReport(
          '<feedback><report_metadata><org_name>o</org_name><report_id>x</report_id></report_metadata><policy_published><domain>d</domain></policy_published></feedback>',
        ),
      /date_range is missing/,
    );
  });
});

describe('alignment arithmetic', () => {
  it('computes organisational domains for relaxed alignment', () => {
    assert.equal(organisationalDomain('mail.insurer-example.com'), 'insurer-example.com');
    assert.equal(organisationalDomain('a.b.c.example.co.uk'), 'example.co.uk');
    assert.equal(organisationalDomain('example.com'), 'example.com');
  });

  it('distinguishes relaxed from strict alignment', () => {
    assert.equal(isAligned('bounce.insurer-example.com', 'mail.insurer-example.com', 'r'), true);
    assert.equal(isAligned('bounce.insurer-example.com', 'mail.insurer-example.com', 's'), false);
    // The planted F1 fault: SPF passes, for a domain that is not the sender's.
    assert.equal(isAligned('bounce.acme-esp.net', 'mail.insurer-example.com', 'r'), false);
  });
});
