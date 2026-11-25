import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const distDirectory = fileURLToPath(new URL('../dist/', import.meta.url));

async function obfuscateDirectory(directory, JavaScriptObfuscator) {
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      await obfuscateDirectory(entryPath, JavaScriptObfuscator);
    } else if (/\.(?:c?js)$/.test(entry.name)) {
      const source = await readFile(entryPath, 'utf8');
      const obfuscated = JavaScriptObfuscator.obfuscate(source, {
        compact: true,
        controlFlowFlattening: false,
        deadCodeInjection: false,
        identifierNamesGenerator: 'hexadecimal',
        renameGlobals: false,
        sourceMap: false,
        stringArray: true,
        stringArrayThreshold: 0.5,
        target: 'node',
      });
      await writeFile(entryPath, obfuscated.getObfuscatedCode());
    }
  }
}

try {
  const { default: JavaScriptObfuscator } = await import('javascript-obfuscator');
  await obfuscateDirectory(distDirectory, JavaScriptObfuscator);
  console.log('[obfuscate-dist] dist obfuscated successfully');
} catch (err) {
  if (err.code === 'ERR_MODULE_NOT_FOUND' || (err.message && err.message.includes('Cannot find package'))) {
    console.log('[obfuscate-dist] javascript-obfuscator not installed in this environment; skipping obfuscation step.');
  } else {
    throw err;
  }
}
