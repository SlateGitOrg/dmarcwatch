import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { decodeEntities, kid, kids, parseXml, textAt, XmlParseError } from '../src/xml.ts';

describe('xml parser', () => {
  it('builds a tree that keeps identically named elements at different depths apart', () => {
    // This is the failure mode a regex scan has: three <domain> elements, all
    // meaning different things. Mixing them up silently produces an alignment
    // report that is wrong in a plausible-looking direction.
    const doc = parseXml(`
      <feedback>
        <policy_published><domain>example.com</domain></policy_published>
        <record>
          <identifiers><domain>ignored</domain><header_from>mail.example.com</header_from></identifiers>
          <auth_results>
            <dkim><domain>esp.net</domain><result>pass</result></dkim>
            <spf><domain>bounce.example.com</domain><result>pass</result></spf>
          </auth_results>
        </record>
      </feedback>`);

    assert.equal(textAt(doc, 'policy_published', 'domain'), 'example.com');
    const rec = kid(doc, 'record')!;
    assert.equal(textAt(rec, 'auth_results', 'dkim', 'domain'), 'esp.net');
    assert.equal(textAt(rec, 'auth_results', 'spf', 'domain'), 'bounce.example.com');
    assert.equal(textAt(rec, 'identifiers', 'header_from'), 'mail.example.com');
  });

  it('strips namespace prefixes so a gateway dialect parses like any other', () => {
    const doc = parseXml(
      `<dm:feedback xmlns:dm="http://dmarc.org/dmarc-xml/0.1"><dm:record><dm:row><dm:count>7</dm:count></dm:row></dm:record></dm:feedback>`,
    );
    assert.equal(doc.name, 'feedback');
    assert.equal(textAt(doc, 'record', 'row', 'count'), '7');
    assert.equal(doc.attrs['xmlns:dm'], 'http://dmarc.org/dmarc-xml/0.1');
  });

  it('handles CDATA, comments, processing instructions, DOCTYPE and self-closing tags', () => {
    const doc = parseXml(`<?xml version="1.0"?>
      <!DOCTYPE feedback SYSTEM "rua.dtd">
      <!-- a comment with <angle> brackets -->
      <feedback>
        <org_name><![CDATA[Acme <Mail> & Co]]></org_name>
        <error/>
        <record a='single' b="double"/>
      </feedback>`);
    assert.equal(textAt(doc, 'org_name'), 'Acme <Mail> & Co');
    assert.equal(kid(doc, 'error')!.text, '');
    assert.deepEqual(kid(doc, 'record')!.attrs, { a: 'single', b: 'double' });
  });

  it('decodes named, decimal and hex character references', () => {
    assert.equal(decodeEntities('a &amp; b &lt;c&gt; &quot;d&quot; &apos;e&apos;'), `a & b <c> "d" 'e'`);
    assert.equal(decodeEntities('&#64;&#x40;'), '@@');
    // An unknown entity is left verbatim rather than silently dropped: losing
    // characters from a domain name would be worse than showing the raw source.
    assert.equal(decodeEntities('&nbsp;x'), '&nbsp;x');
  });

  it('collects repeated siblings in document order', () => {
    const doc = parseXml(
      '<auth_results><dkim><domain>a</domain></dkim><dkim><domain>b</domain></dkim><spf><domain>c</domain></spf></auth_results>',
    );
    assert.deepEqual(
      kids(doc, 'dkim').map((d) => textAt(d, 'domain')),
      ['a', 'b'],
    );
    assert.equal(kids(doc, 'spf').length, 1);
  });

  it('rejects malformed documents instead of returning a half-built tree', () => {
    const cases: [string, RegExp][] = [
      ['<feedback><record></feedback>', /does not match/],
      ['<feedback><record>', /unclosed element/],
      ['<feedback attr=unquoted></feedback>', /unquoted attribute value/],
      ['<feedback><!-- never ends </feedback>', /unterminated comment/],
      ['   ', /no elements/],
      ['</feedback>', /no open element/],
    ];
    for (const [src, re] of cases) {
      assert.throws(() => parseXml(src), (e: unknown) => e instanceof XmlParseError && re.test((e as Error).message), src);
    }
  });

  it('returns undefined, not empty string, for an absent path', () => {
    // Providers omit optional elements; "absent" and "present but empty" are
    // different facts and the reader downstream depends on telling them apart.
    const doc = parseXml('<feedback><report_metadata><error></error></report_metadata></feedback>');
    assert.equal(textAt(doc, 'report_metadata', 'error'), '');
    assert.equal(textAt(doc, 'report_metadata', 'extra_contact_info'), undefined);
  });
});
