/**
 * A minimal, dependency-free XML reader sized for DMARC aggregate reports.
 *
 * Why hand-rolled rather than a regex sweep: RUA reports nest the same element
 * name at two depths (`<source_ip>` is unique, but `<domain>` appears inside
 * `policy_published`, `identifiers` AND both `auth_results` children). A regex
 * that greps for `<domain>` therefore silently mixes the policy domain with the
 * DKIM signing domain, which is exactly the bug that makes an alignment report
 * wrong in the direction that looks plausible. A real tree keeps them apart.
 *
 * Scope limits (deliberate): no DTD, no namespace resolution beyond keeping the
 * prefix off the local name, no entity declarations beyond the five predefined
 * ones plus numeric character references. DMARC RUA XML uses none of them.
 */

export type XmlNode = {
  name: string;
  attrs: Record<string, string>;
  children: XmlNode[];
  /** Concatenated direct text content, whitespace-trimmed. */
  text: string;
};

export class XmlParseError extends Error {
  offset: number;
  constructor(message: string, offset: number) {
    super(`${message} (at offset ${offset})`);
    this.name = 'XmlParseError';
    this.offset = offset;
  }
}

const NAMED_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
};

export function decodeEntities(raw: string): string {
  return raw.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body: string) => {
    if (body.startsWith('#x') || body.startsWith('#X')) {
      const code = Number.parseInt(body.slice(2), 16);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    if (body.startsWith('#')) {
      const code = Number.parseInt(body.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    const named = NAMED_ENTITIES[body];
    return named === undefined ? whole : named;
  });
}

/** Strip a namespace prefix: `dmarc:record` -> `record`. */
function localName(qualified: string): string {
  const colon = qualified.indexOf(':');
  return colon === -1 ? qualified : qualified.slice(colon + 1);
}

const NAME_START = /[A-Za-z_:]/;
const NAME_CHAR = /[A-Za-z0-9_:.\-]/;

export function parseXml(source: string): XmlNode {
  let i = 0;
  const n = source.length;
  const stack: XmlNode[] = [];
  let root: XmlNode | null = null;

  const fail = (msg: string): never => {
    throw new XmlParseError(msg, i);
  };

  const readName = (): string => {
    const start = i;
    if (i >= n || !NAME_START.test(source[i]!)) fail('expected element name');
    while (i < n && NAME_CHAR.test(source[i]!)) i++;
    return source.slice(start, i);
  };

  const skipSpace = (): void => {
    while (i < n && /\s/.test(source[i]!)) i++;
  };

  const pushText = (raw: string): void => {
    const top = stack[stack.length - 1];
    if (top === undefined) return; // text outside the root element: ignored
    top.text += decodeEntities(raw);
  };

  while (i < n) {
    const lt = source.indexOf('<', i);
    if (lt === -1) {
      pushText(source.slice(i));
      break;
    }
    if (lt > i) pushText(source.slice(i, lt));
    i = lt;

    if (source.startsWith('<!--', i)) {
      const end = source.indexOf('-->', i + 4);
      if (end === -1) fail('unterminated comment');
      i = end + 3;
      continue;
    }
    if (source.startsWith('<![CDATA[', i)) {
      const end = source.indexOf(']]>', i + 9);
      if (end === -1) fail('unterminated CDATA section');
      const top = stack[stack.length - 1];
      if (top !== undefined) top.text += source.slice(i + 9, end);
      i = end + 3;
      continue;
    }
    if (source.startsWith('<?', i)) {
      const end = source.indexOf('?>', i + 2);
      if (end === -1) fail('unterminated processing instruction');
      i = end + 2;
      continue;
    }
    if (source.startsWith('<!', i)) {
      // DOCTYPE or similar declaration; skip to the matching '>' at depth 0.
      let depth = 0;
      i += 2;
      while (i < n) {
        const c = source[i]!;
        if (c === '<') depth++;
        else if (c === '>') {
          if (depth === 0) {
            i++;
            break;
          }
          depth--;
        }
        i++;
      }
      continue;
    }

    if (source.startsWith('</', i)) {
      i += 2;
      const name = localName(readName());
      skipSpace();
      if (source[i] !== '>') fail('malformed closing tag');
      i++;
      const top = stack.pop();
      if (top === undefined) fail(`closing tag </${name}> with no open element`);
      if (top!.name !== name) fail(`closing tag </${name}> does not match <${top!.name}>`);
      top!.text = top!.text.trim();
      if (stack.length === 0) root = top!;
      continue;
    }

    // Opening tag.
    i++;
    const name = localName(readName());
    const node: XmlNode = { name, attrs: {}, children: [], text: '' };
    for (;;) {
      skipSpace();
      if (i >= n) fail('unterminated element');
      if (source.startsWith('/>', i)) {
        i += 2;
        const parent = stack[stack.length - 1];
        if (parent === undefined) {
          if (root !== null) fail('multiple root elements');
          root = node;
        } else {
          parent.children.push(node);
        }
        break;
      }
      if (source[i] === '>') {
        i++;
        const parent = stack[stack.length - 1];
        if (parent === undefined && root !== null) fail('multiple root elements');
        if (parent !== undefined) parent.children.push(node);
        stack.push(node);
        break;
      }
      // Attribute names keep their prefix: `xmlns:dm` is not an attribute
      // called `dm`, and namespace declarations are worth preserving verbatim.
      const attrName = readName();
      skipSpace();
      if (source[i] !== '=') fail(`attribute ${attrName} has no value`);
      i++;
      skipSpace();
      const quote = source[i];
      if (quote !== '"' && quote !== "'") fail('unquoted attribute value');
      i++;
      const close = source.indexOf(quote, i);
      if (close === -1) fail('unterminated attribute value');
      node.attrs[attrName] = decodeEntities(source.slice(i, close));
      i = close + 1;
    }
  }

  if (stack.length > 0) {
    throw new XmlParseError(`unclosed element <${stack[stack.length - 1]!.name}>`, n);
  }
  if (root === null) throw new XmlParseError('document contains no elements', n);
  return root;
}

/** All direct children with the given local name. */
export function kids(node: XmlNode | undefined, name: string): XmlNode[] {
  if (node === undefined) return [];
  return node.children.filter((c) => c.name === name);
}

/** First direct child with the given local name, or undefined. */
export function kid(node: XmlNode | undefined, name: string): XmlNode | undefined {
  if (node === undefined) return undefined;
  return node.children.find((c) => c.name === name);
}

/**
 * Text of the first child at the given path, or undefined if any step is
 * missing. Returning undefined rather than '' matters: providers omit optional
 * elements, and "absent" must not collapse into "present but empty".
 */
export function textAt(node: XmlNode | undefined, ...path: string[]): string | undefined {
  let cur: XmlNode | undefined = node;
  for (const step of path) {
    cur = kid(cur, step);
    if (cur === undefined) return undefined;
  }
  return cur.text;
}
