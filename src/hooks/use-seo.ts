import { useEffect } from 'react';

interface SEOProps {
  title: string;
  description: string;
  url?: string;
  image?: string;
  type?: string;
  keywords?: string[];
  publishedTime?: string;
  author?: string;
}

export function useSEO({ 
  title, 
  description, 
  url, 
  image, 
  type = 'article',
  keywords = [],
  publishedTime,
  author = 'Zuk4r1'
}: SEOProps) {
  useEffect(() => {
    // 1. Actualizar título del documento
    document.title = `${title} | Zuk4r1 Blog`;

    // 2. Helper para actualizar meta tags
    const updateMeta = (name: string, content: string, attribute = 'name') => {
      let element = document.querySelector(`meta[${attribute}="${name}"]`);
      if (!element) {
        element = document.createElement('meta');
        element.setAttribute(attribute, name);
        document.head.appendChild(element);
      }
      element.setAttribute('content', content);
    };

    // 3. Meta Tags Básicos
    updateMeta('description', description);
    if (keywords.length > 0) {
      updateMeta('keywords', keywords.join(', '));
    }

    // 4. Open Graph (Facebook/LinkedIn)
    updateMeta('og:title', title, 'property');
    updateMeta('og:description', description, 'property');
    updateMeta('og:type', type, 'property');
    if (url) updateMeta('og:url', url, 'property');
    if (image) updateMeta('og:image', image, 'property');
    if (publishedTime) updateMeta('article:published_time', publishedTime, 'property');

    // 5. Twitter Card
    updateMeta('twitter:title', title, 'property');
    updateMeta('twitter:description', description, 'property');
    updateMeta('twitter:card', 'summary_large_image', 'property');
    if (image) updateMeta('twitter:image', image, 'property');

    // 6. JSON-LD (Structured Data para Google)
    // Esto es CLAVE para "búsquedas relacionadas" y rich snippets
    const scriptId = 'seo-json-ld';
    let script = document.getElementById(scriptId) as HTMLScriptElement;
    
    if (!script) {
      script = document.createElement('script');
      script.id = scriptId;
      script.type = 'application/ld+json';
      document.head.appendChild(script);
    }

    const jsonLd: Record<string, any> = {
      '@context': 'https://schema.org',
      '@type': type === 'article' ? 'BlogPosting' : 'WebSite',
      'headline': title,
      'description': description,
      'author': {
        '@type': 'Person',
        'name': author
      },
      ...(image && { 'image': image }),
      ...(url && { 'url': url }),
      ...(publishedTime && { 'datePublished': publishedTime }),
      'mainEntityOfPage': {
        '@type': 'WebPage',
        '@id': url || window.location.href
      }
    };

    script.text = JSON.stringify(jsonLd);

    // Cleanup (opcional, pero buena práctica)
    return () => {
      // No eliminamos tags persistentes para evitar parpadeos, 
      // pero el próximo render los actualizará.
    };

  }, [title, description, url, image, type, keywords, publishedTime, author]);
}
