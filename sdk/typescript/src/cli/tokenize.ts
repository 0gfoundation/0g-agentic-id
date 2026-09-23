/**
 * @file tokenize.ts
 * @description Splitting a REPL line into arguments, the way a shell does.
 *
 * Outside the REPL the user's shell does this and the CLI never sees quotes.
 * Inside it, a bare `line.split(/\s+/)` made every value containing a space
 * unreachable — `others={"tools": {"bash": true}}` arrived as four
 * arguments, and the error message helpfully suggested quoting, which the
 * splitter then handed through as literal `'` characters. Quoting has to
 * actually work, or the advice is a dead end.
 *
 * The grammar is the small familiar one, and deliberately no larger:
 *
 *   'single'   everything literal up to the next single quote
 *   "double"   literal too, except `\"` and `\\`
 *   \x         outside quotes, the next character verbatim (so `\ ` is a space)
 *   {…} […]    a JSON literal WHERE A VALUE STARTS — copied through exactly as
 *              typed, to its matching close: spaces, nesting and quotes alike
 *
 * That last rule is what keeps a shell splitter honest about JSON. Quote
 * characters are how a shell protects a value, but they are also what JSON is
 * MADE of, so stripping them turns `others={"a":1}` — the unquoted form the
 * help and the GUIDE print — into `others={a:1}`, which parses as nothing.
 * A literal opening where a value begins (the start of a token, or right after
 * an `=`) is therefore data: copied, not interpreted. Elsewhere a bracket is
 * an ordinary character, so `/api/x[0]` is still one plain token.
 *
 * No variable expansion, no globbing, no operators — a REPL argument is data,
 * and a splitter that interprets it would be a surprise, not a convenience.
 * Adjacent pieces join into one token (`others='{"a": 1}'` is one word),
 * which is the whole point.
 *
 * A command whose LAST argument is free-form text rather than a value in a
 * list — `call <id> <path> <json-body>` — should not be run through this at
 * all: see {@link splitHead}.
 */

/**
 * Split a command line into tokens. An unterminated quote is NOT an error:
 * the user is mid-thought at an interactive prompt, so the run of text is
 * taken as written and the caller's own grammar check reports whatever is
 * wrong with it — a parse error about quoting would just be noise on top.
 */
export function tokenize(line: string): string[] {
  return scan(line, Infinity).head;
}

/**
 * Split off the first `n` tokens and hand the REST OF THE LINE back verbatim.
 *
 * The shell-style splitter is the wrong tool for an argument that is free-form
 * text. `call 42 /api/x {"a": 1}` has a fixed head — command, agent, path —
 * and then a body that is whatever the user typed, quotes and inner spacing
 * included, on its way to an agent that will parse it. Tokenizing that and
 * re-joining the pieces with a single space is a guess about what was typed;
 * taking the remainder of the line is not a guess.
 *
 * `rest` has no leading whitespace, and is '' when the line holds no more
 * than `n` tokens.
 */
export function splitHead(line: string, n: number): { head: string[]; rest: string } {
  return scan(line, n);
}

/** The one scanner behind both entry points: it stops after `limit` tokens
 *  and reports whatever is left of the line untouched. */
function scan(line: string, limit: number): { head: string[]; rest: string } {
  const head: string[] = [];
  let cur = '';
  let started = false; // distinguishes '' (a real empty token) from no token
  let quote: '"' | "'" | null = null;

  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quote === "'") {
      if (c === "'") quote = null;
      else cur += c;
      continue;
    }
    if (quote === '"') {
      if (c === '"') quote = null;
      else if (c === '\\' && (line[i + 1] === '"' || line[i + 1] === '\\')) cur += line[++i];
      else cur += c;
      continue;
    }
    // The head the caller asked for is complete: everything from the next
    // non-space character on belongs to it verbatim.
    if (!started && head.length >= limit) {
      if (/\s/.test(c)) continue;
      return { head, rest: line.slice(i) };
    }
    if (c === "'" || c === '"') { quote = c; started = true; continue; }
    if ((c === '{' || c === '[') && (!started || line[i - 1] === '=')) {
      const end = literalEnd(line, i);
      cur += line.slice(i, end);
      i = end - 1;
      started = true;
      continue;
    }
    if (c === '\\' && i + 1 < line.length) { cur += line[++i]; started = true; continue; }
    if (/\s/.test(c)) {
      if (started) { head.push(cur); cur = ''; started = false; }
      continue;
    }
    cur += c;
    started = true;
  }
  if (started) head.push(cur);
  return { head, rest: '' };
}

/** Index just past the `}`/`]` closing the literal that opens at `start`.
 *  Brackets inside a JSON string don't count. An unbalanced literal runs to
 *  the end of the line — the same "taken as written" treatment an
 *  unterminated quote gets, leaving the grammar check to report it. */
function literalEnd(line: string, start: number): number {
  let depth = 0;
  let inString = false;
  for (let i = start; i < line.length; i++) {
    const c = line[i];
    if (inString) {
      if (c === '\\') i++;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; continue; }
    if (c === '{' || c === '[') depth++;
    else if ((c === '}' || c === ']') && --depth === 0) return i + 1;
  }
  return line.length;
}
