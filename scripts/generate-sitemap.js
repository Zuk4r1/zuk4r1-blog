import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Configuración para ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const POSTS_DIR = path.join(__dirname, '../src/posts');
const PUBLIC_DIR = path.join(__dirname, '../public');
const SITE_URL = 'https://www.blog-cyber.co';

// Función simple para extraer metadatos del frontmatter sin dependencias externas
function parseFrontmatter(content) {
  const match = content.match(/^---\s*([\s\S]*?)\s*---/);
  if (!match) return { date: null };

  const frontmatter = match[1];
  const dateMatch = frontmatter.match(/date:\s*["']?([^"'\n]+)["']?/);

  return {
    date: dateMatch ? dateMatch[1].trim() : null,
  };
}

function formatUrl(loc, { lastmod = null, changefreq = 'monthly', priority = '0.8' } = {}) {
  return [
    '  <url>',
    `    <loc>${SITE_URL}${loc}</loc>`,
    lastmod ? `    <lastmod>${lastmod}</lastmod>` : null,
    `    <changefreq>${changefreq}</changefreq>`,
    `    <priority>${priority}</priority>`,
    '  </url>',
  ]
    .filter(Boolean)
    .join('\n');
}

export function generateSitemap() {
  console.log('Generando sitemap...');
  
  if (!fs.existsSync(POSTS_DIR)) {
    console.error('No se encontró el directorio de posts:', POSTS_DIR);
    return;
  }

  // Crear directorio public si no existe
  if (!fs.existsSync(PUBLIC_DIR)) {
    fs.mkdirSync(PUBLIC_DIR, { recursive: true });
  }

  const files = fs.readdirSync(POSTS_DIR).filter(file => file.endsWith('.md'));

  const staticUrls = [
    { loc: '/', changefreq: 'weekly', priority: '1.0' },
    { loc: '/about', changefreq: 'weekly', priority: '0.8' },
    { loc: '/content', changefreq: 'weekly', priority: '0.8' },
    { loc: '/tags', changefreq: 'weekly', priority: '0.8' },
  ];

  const postUrls = files.map(file => {
    const content = fs.readFileSync(path.join(POSTS_DIR, file), 'utf-8');
    const data = parseFrontmatter(content);

    // Lógica de ID idéntica a la app (src/lib/posts.ts)
    const baseName = file.replace(/\.md$/i, '');
    const parts = baseName.split('-');
    const last3 = parts.slice(-3);
    const [yyyy, mm, dd] = last3;
    const hasDateInName = /^\d{4}$/.test(yyyy || '') && /^\d{2}$/.test(mm || '') && /^\d{2}$/.test(dd || '');
    const rawId = hasDateInName ? parts.slice(0, -3).join('-') : baseName;

    const id = rawId
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .replace(/[^a-z0-9-]+/g, '-')
      .replace(/^-+|-+$/g, '');

    const lastmod = data.date && /^\d{4}-\d{2}-\d{2}$/.test(data.date)
      ? data.date
      : new Date().toISOString().split('T')[0];

    return {
      loc: `/post/${id}`,
      lastmod,
      changefreq: 'monthly',
      priority: '0.8',
    };
  });

  const urls = [...staticUrls, ...postUrls]
    .sort((a, b) => a.loc.localeCompare(b.loc))
    .map(entry => formatUrl(entry.loc, entry));

  const sitemap = ['<?xml version="1.0" encoding="UTF-8"?>',
    '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ...urls,
    '</urlset>',
  ].join('\n');

  fs.writeFileSync(path.join(PUBLIC_DIR, 'sitemap.xml'), sitemap);
  console.log(`Sitemap generado con ${urls.length} posts en ${path.join(PUBLIC_DIR, 'sitemap.xml')}`);
}

// Ejecutar solo cuando se invoque directamente con Node
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  generateSitemap();
}
