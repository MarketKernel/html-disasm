/**
 * An esbuild plugin for big data that the page needs only sometimes:
 * `import text from './file.json?text'` gives the file as a string (JSON
 * without its whitespace), which the page parses the first time it needs it.
 * A string costs the page little to load, where the same data as an object
 * literal would be parsed, every bit of it, at every start.
 */
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export const textPlugin = {
  name: 'text',
  setup(build) {
    build.onResolve({ filter: /\?text$/ }, (args) => ({ path: resolve(args.resolveDir, args.path.replace(/\?text$/, '')), namespace: 'text' }));
    build.onLoad({ filter: /.*/, namespace: 'text' }, async (args) => {
      let text = await readFile(args.path, 'utf8');
      if (args.path.endsWith('.json')) text = JSON.stringify(JSON.parse(text));
      return { contents: `export default ${JSON.stringify(text)};`, loader: 'js', watchFiles: [args.path] };
    });
  },
};
