// Shared helpers for Node vm-context tests against template <script> blocks --
// step 4 of CLAUDE.md's testing standard. Collapses the extractFn/pass-fail
// boilerplate that used to get re-typed into every scratch test file.
//
// Usage (from a scratch test script, absolute path into the repo):
//   const { extractFn, makeChecker } = require('D:/Github/micro-dfir/tools/vm_test_harness');
//   const { check, summary } = makeChecker();
//   check(1 + 1 === 2, 'sanity');
//   summary();

// Extracts a top-level `function name(...) { ... }` (including a leading
// `async `) from a template's inline script source, by brace-depth counting
// -- not a regex match on the body, since a function can contain nested
// braces (template literals, object literals) a naive regex would cut short.
function extractFn(source, name) {
    let start = source.indexOf(`function ${name}(`);
    if (start === -1) throw new Error(`function not found: ${name}`);
    if (source.slice(Math.max(0, start - 6), start) === 'async ') start -= 6;
    let i = source.indexOf('{', start);
    let depth = 0;
    for (; i < source.length; i++) {
        if (source[i] === '{') depth++;
        else if (source[i] === '}') { depth--; if (depth === 0) { i++; break; } }
    }
    return source.slice(start, i);
}

// A top-level const/let evaluated via vm.runInContext(code, sandbox) does not
// attach as an enumerable property on sandbox -- read it back with a second
// vm.runInContext('CONST_NAME', sandbox) call (documented in CLAUDE.md).
function readConst(vm, sandbox, name) {
    return vm.runInContext(name, sandbox);
}

function makeChecker() {
    let pass = 0, fail = 0;
    function check(cond, msg) {
        if (cond) { pass++; console.log('ok:', msg); }
        else { fail++; console.log('FAIL:', msg); }
    }
    function summary() {
        console.log();
        console.log(`${pass} passed, ${fail} failed`);
        if (fail) process.exitCode = 1;
    }
    return { check, summary };
}

module.exports = { extractFn, readConst, makeChecker };
