import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const panelRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (relativePath) => fs.readFileSync(path.join(panelRoot, relativePath), 'utf8');
const exists = (relativePath) => fs.existsSync(path.join(panelRoot, relativePath));

const failures = [];
const check = (condition, message) => {
  if (!condition) failures.push(message);
};

const app = read('src/App.tsx');
const foundation = read('src/styles-foundation.css');
const index = read('index.html');

check(app.includes('data-route-heading'), 'route headings must be focusable after navigation');
check(
  app.includes('window.requestAnimationFrame'),
  'route changes must schedule scroll/focus restoration',
);
check(
  app.includes('aria-labelledby="route-heading"'),
  'main content must be labelled by the route heading',
);
check(foundation.includes('@font-face'), 'fonts must be self-hosted with @font-face');
check(
  !/fonts\.googleapis\.com|fonts\.gstatic\.com|@import\s+url\(/i.test(foundation),
  'foundation CSS must not load remote fonts',
);
check(
  !/url\(\s*['"]\/fonts\//.test(foundation),
  'font URLs must remain relative for GitHub Pages subpaths',
);
check(foundation.includes('align-items: start'), 'editor grids must not stretch the XP preview');
check(
  foundation.includes('grid-auto-rows: max-content'),
  'XP editor columns must size to their own content',
);
check(
  foundation.includes('height: max-content'),
  'XP editor cards must not inherit the taller column height',
);
check(
  foundation.includes('aspect-ratio: 1.86 / 1'),
  'XP preview needs a stable desktop aspect ratio',
);
check(foundation.includes('flex: 0 0 44px'), 'XP color swatches must keep a square touch target');
check(
  foundation.includes('aspect-ratio: 1;'),
  'XP color swatches must keep a circular aspect ratio',
);
check(
  foundation.includes('max-width: 44px'),
  'XP color swatches must not be compressed by flex layout',
);
check(
  foundation.includes('--panel-control-height: 44px'),
  'interactive controls need a 44px minimum token',
);
check(
  foundation.includes(".panel-main .toggle-field input[type='checkbox']") &&
    foundation.includes('min-height: 22px'),
  'toggle controls must keep their compact horizontal dimensions inside a touch-friendly field',
);
check(
  foundation.includes('.panel-sidebar .nav'),
  'sidebar navigation must be scoped and touch friendly',
);
check(foundation.includes('prefers-reduced-motion'), 'motion must have a reduced-motion fallback');
check(index.includes("font-src 'self'"), 'CSP must allow only self-hosted fonts');

for (const font of [
  'public/fonts/vozen-outfit-400.woff2',
  'public/fonts/vozen-outfit-400-ext.woff2',
  'public/fonts/vozen-jetbrains-mono-400.woff2',
]) {
  check(exists(font), `missing self-hosted font: ${font}`);
}

// This catches the two most common regressions in generated UI copy without
// rejecting valid Portuguese accents.  The second byte of a UTF-8 mojibake
// pair is in the U+0080–U+00BF range; a valid Portuguese Ã (for example) is
// followed by a different uppercase character.
const api = read('src/api.ts');
check(
  /if \(oauthLoginPending\) persistSessionBearer\(oauthSession\)/.test(api) &&
    api.includes("sessionStorage.removeItem('vh_oauth_verifier')") &&
    (api.match(/persistSessionBearer\(oauthSession\)/g) ?? []).length === 1,
  '#session= fragment must only be accepted after a login started in this tab (login CSRF)',
);

const mojibake = /Ã[\u0080-\u00bf]|Â[\u0080-\u00bf]|â[\u0080-\u00bf]|�/u;
for (const relativePath of [
  'src/App.tsx',
  'src/api.ts',
  'src/main.tsx',
  'src/styles.css',
  'src/styles-foundation.css',
  'index.html',
]) {
  const content = read(relativePath);
  check(!mojibake.test(content), `mojibake detected in ${relativePath}`);
}

const distRoot = path.join(panelRoot, 'dist');
if (fs.existsSync(distRoot)) {
  const files = fs.readdirSync(distRoot, { recursive: true });
  for (const file of files) {
    const fullPath = path.join(distRoot, file);
    if (!fs.statSync(fullPath).isFile() || !/\.(?:html|css|js|json)$/i.test(fullPath)) continue;
    const content = fs.readFileSync(fullPath, 'utf8');
    check(!mojibake.test(content), `mojibake leaked into ${path.relative(panelRoot, fullPath)}`);
  }
}

if (failures.length > 0) {
  console.error(`UI verification failed (${failures.length}):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(
    'UI verification passed: fonts, routing focus, XP layout, controls and copy are guarded.',
  );
}
