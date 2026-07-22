import chokidar from 'chokidar';
import path from 'path';
import { fileURLToPath } from 'url';
import { generateSitemap } from './generate-sitemap.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const POSTS_DIR = path.join(__dirname, '../src/posts');

console.log('Iniciando watcher de posts en:', POSTS_DIR);

// Generar inicialmente
try {
  generateSitemap();
} catch (e) {
  console.error('Error generando sitemap inicial:', e);
}

const watcher = chokidar.watch(POSTS_DIR, {
  persistent: true,
  ignoreInitial: true,
  depth: 0,
  awaitWriteFinish: {
    stabilityThreshold: 200,
    pollInterval: 100
  }
});

const regen = (event, p) => {
  console.log(`Evento: ${event} -> ${p}. Regenerando sitemap...`);
  try {
    generateSitemap();
  } catch (e) {
    console.error('Error regenerando sitemap:', e);
  }
};

watcher.on('add', p => regen('add', p));
watcher.on('change', p => regen('change', p));
watcher.on('unlink', p => regen('unlink', p));

process.on('SIGINT', async () => {
  console.log('Deteniendo watcher...');
  await watcher.close();
  process.exit(0);
});
