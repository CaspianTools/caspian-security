import { buildLineStates, isInsideComment, isInsideStringContent, cleanLineState } from '../scanContext';

describe('buildLineStates — F11 multi-line context', () => {
  it('marks lines inside a template literal as template content', () => {
    const text =
      'const html = `\n' +           // line 0: opens a template literal
      '  <div>password</div>\n' +     // line 1: inside template
      '  <span>still here</span>\n' + // line 2: inside template
      '`;\n' +                        // line 3: closes — but this line STARTS inside
      'const after = 1;\n';            // line 4: outside again
    const s = buildLineStates(text);
    expect(s[0].startsInsideTemplateLiteral).toBe(false);
    expect(s[1].startsInsideTemplateLiteral).toBe(true);
    expect(s[2].startsInsideTemplateLiteral).toBe(true);
    expect(s[3].startsInsideTemplateLiteral).toBe(true);
    expect(s[4].startsInsideTemplateLiteral).toBe(false);
  });

  it('treats `${}` expressions as code, not template content', () => {
    // When the template expression spans a line, the next line's state is code.
    const text =
      'const html = `${\n' +          // line 0: enters template, then ${
      '  someVar + 1\n' +              // line 1: this is CODE, not template content
      '}`;\n';                          // line 2: closes expr, closes template
    const s = buildLineStates(text);
    expect(s[1].startsInsideTemplateLiteral).toBe(false);
    expect(s[1].templateExprDepth).toBe(1);
  });

  it('marks lines inside a block comment as comment content', () => {
    const text =
      '/**\n' +                       // line 0
      ' * multi-line JSDoc\n' +       // line 1: inside block comment
      ' * with password = "hunter2"\n' + // line 2: inside
      ' */\n' +                       // line 3: closes, but starts inside
      'const x = 1;\n';                // line 4: outside
    const s = buildLineStates(text);
    expect(s[0].startsInsideBlockComment).toBe(false);
    expect(s[1].startsInsideBlockComment).toBe(true);
    expect(s[2].startsInsideBlockComment).toBe(true);
    expect(s[3].startsInsideBlockComment).toBe(true);
    expect(s[4].startsInsideBlockComment).toBe(false);
  });

  it('keeps clean state across a single-quoted string (no line-continuation)', () => {
    // Unescaped newline terminates single/double quoted strings — next line
    // must be in a clean state.
    const text =
      "const s = 'unterminated\n" +
      'const t = 2;\n';
    const s = buildLineStates(text);
    expect(s[1].startsInsideQuotedString).toBe(false);
  });
});

describe('isInsideStringContent — with multi-line context', () => {
  it('returns true for a match in the middle of a multi-line template literal', () => {
    // Line-scoped false negative without F11: this line has zero backticks of its own.
    const line = '  <div>password</div>';
    const state = {
      startsInsideQuotedString: false,
      startsInsideTemplateLiteral: true,
      startsInsideBlockComment: false,
      templateExprDepth: 0,
    };
    expect(isInsideStringContent(line, 10, state)).toBe(true);
  });

  it('returns false for a match that comes AFTER the template literal closes', () => {
    const line = '`; const x = 1;';
    const state = {
      startsInsideQuotedString: false,
      startsInsideTemplateLiteral: true,
      startsInsideBlockComment: false,
      templateExprDepth: 0,
    };
    // Column 10 is on `x` — in code, after the template closes at col 0.
    expect(isInsideStringContent(line, 10, state)).toBe(false);
  });

  it('falls back to line-scoped logic when given a clean state', () => {
    const line = 'const pw = "hunter2";';
    // Column 14 is inside the double-quoted string.
    expect(isInsideStringContent(line, 14, cleanLineState())).toBe(true);
    // Column 6 (in `pw`) is NOT inside a string.
    expect(isInsideStringContent(line, 6, cleanLineState())).toBe(false);
  });
});

describe('isInsideComment — with multi-line context', () => {
  it('returns true for any column on a line inside an unterminated block comment', () => {
    const line = ' * some doc text with a password';
    const state = {
      startsInsideQuotedString: false,
      startsInsideTemplateLiteral: false,
      startsInsideBlockComment: true,
      templateExprDepth: 0,
    };
    expect(isInsideComment(line, 20, state)).toBe(true);
  });

  it('returns false after a block comment closes on this line', () => {
    const line = ' */ const x = 1;';
    const state = {
      startsInsideQuotedString: false,
      startsInsideTemplateLiteral: false,
      startsInsideBlockComment: true,
      templateExprDepth: 0,
    };
    expect(isInsideComment(line, 1, state)).toBe(true);   // inside the */
    expect(isInsideComment(line, 10, state)).toBe(false); // past the close
  });
});
