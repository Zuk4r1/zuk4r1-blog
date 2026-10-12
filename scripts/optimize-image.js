import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import sharp from 'sharp';

// Configuración para ES Modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PUBLIC_IMAGENES_DIR = path.join(__dirname, '../public/imagenes');
const MAX_WIDTH = 1600;
const WEBP_QUALITY = 80;

function toSlug(input) {
  return input
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .replace(/-{2,}/g, '-');
}

function printUsage() {
  console.log(`
Uso:
  node scripts/optimize-image.js <archivo-de-entrada> <slug-del-post> [nombre-salida] [--width=1600]

Ejemplos:
  node scripts/optimize-image.js ~/capturas/burp-request.png hackthebox-jerry
  node scripts/optimize-image.js ~/capturas/cover.png hackthebox-jerry cover --width=1200

Convierte la imagen a .webp optimizado y la deja en:
  public/imagenes/<slug-del-post>/<nombre-salida>.webp

Esa ruta ya es la que entiende el renderer del blog, así que en el post
solo hace falta referenciarla:
  - coverImage: "/imagenes/<slug-del-post>/<nombre-salida>.webp"   (frontmatter)
  - ![alt](/imagenes/<slug-del-post>/<nombre-salida>.webp)         (cuerpo del post)
`);
}

async function optimizeImage(inputPath, slugArg, outputNameArg, maxWidthArg) {
  if (!fs.existsSync(inputPath)) {
    console.error(`No existe el archivo de entrada: ${inputPath}`);
    process.exitCode = 1;
    return;
  }

  const slug = toSlug(slugArg);
  if (!slug) {
    console.error(`Slug de post inválido: "${slugArg}"`);
    process.exitCode = 1;
    return;
  }

  const outputDir = path.join(PUBLIC_IMAGENES_DIR, slug);
  fs.mkdirSync(outputDir, { recursive: true });

  const baseName = outputNameArg
    ? toSlug(outputNameArg)
    : toSlug(path.basename(inputPath, path.extname(inputPath)));
  const outputPath = path.join(outputDir, `${baseName}.webp`);

  const maxWidth = maxWidthArg || MAX_WIDTH;

  const image = sharp(inputPath).rotate();
  const metadata = await image.metadata();

  if (metadata.width && metadata.width > maxWidth) {
    image.resize({ width: maxWidth });
  }

  await image.webp({ quality: WEBP_QUALITY }).toFile(outputPath);

  const { size: inputSize } = fs.statSync(inputPath);
  const { size: outputSize } = fs.statSync(outputPath);
  const savedPct = (((inputSize - outputSize) / inputSize) * 100).toFixed(1);
  const publicPath = `/imagenes/${slug}/${baseName}.webp`;

  console.log(`Generado: ${outputPath}`);
  console.log(`  ${(inputSize / 1024).toFixed(1)} KB -> ${(outputSize / 1024).toFixed(1)} KB (${savedPct}% menos)`);
  console.log(`  Ruta para usar en el post: ${publicPath}`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  const widthFlag = process.argv.slice(2).find((a) => a.startsWith('--width='));
  const maxWidth = widthFlag ? parseInt(widthFlag.split('=')[1], 10) : undefined;

  const [inputPath, slugArg, outputNameArg] = args;

  if (!inputPath || !slugArg) {
    printUsage();
    process.exitCode = 1;
  } else {
    optimizeImage(inputPath, slugArg, outputNameArg, maxWidth).catch((error) => {
      console.error('Error optimizando la imagen:', error);
      process.exitCode = 1;
    });
  }
}
