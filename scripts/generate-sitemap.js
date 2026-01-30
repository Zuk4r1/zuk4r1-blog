import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Configuración para ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const POSTS_DIR = path.join(__dirname, '../src/posts');
const PUBLIC_DIR = path.join(__dirname, '../public');
const SITE_URL = 'https://zuk4r1-blog.com'; // ¡Cambia esto por tu dominio real!

// Función simple para extraer metadatos del frontmatter sin dependencias externas
function parseFrontmatter(content) {
  const match = content.match(/^---\s*([\s\S]*?)\s*---/);
  if (!match) return { date: null };

  const frontmatter = match[1];
  const dateMatch = frontmatter.match(/date:\s*["']?([^"'\n]+)["']?/);
  
  return {
    date: dateMatch ? dateMatch[1] : null
  };
}

function generateSitemap() {
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
  
  const urls = files.map(file => {
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

    return `
  <url>
    <loc>${SITE_URL}/post/${id}</loc>
    <lastmod>${data.date || new Date().toISOString().split('T')[0]}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>`;
  });

  const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${SITE_URL}/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>${urls.join('')}
</urlset>`;

  fs.writeFileSync(path.join(PUBLIC_DIR, 'sitemap.xml'), sitemap);
  console.log(`Sitemap generado con ${urls.length} posts en ${path.join(PUBLIC_DIR, 'sitemap.xml')}`);
}

generateSitemap();
