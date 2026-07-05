import { Routes as RouterRoutes, Route } from 'react-router-dom';
import { AnimatePresence } from 'framer-motion';
import { lazy, Suspense, ReactNode } from 'react';

// Lazy loading de páginas para optimizar bundle inicial
const Index = lazy(() => import('@/pages/Index').then(m => ({ default: m.Index })));
const About = lazy(() => import('@/pages/About').then(m => ({ default: m.About })));
const Content = lazy(() => import('@/pages/Content').then(m => ({ default: m.Content })));
const Tags = lazy(() => import('@/pages/Tags').then(m => ({ default: m.Tags })));
const TagPosts = lazy(() => import('@/pages/TagPosts').then(m => ({ default: m.TagPosts })));
const Post = lazy(() => import('@/pages/Post').then(m => ({ default: m.Post })));
const NotFound = lazy(() => import('@/pages/NotFound').then(m => ({ default: m.NotFound })));

/**
 * Componente de fallback mientras carga una página
 */
function PageLoader(): ReactNode {
  return (
    <div className="flex items-center justify-center min-h-screen">
      <div className="text-center space-y-4">
        <div className="relative w-12 h-12 mx-auto">
          <div className="absolute inset-0 border-t-2 border-cyber-primary rounded-full animate-spin"></div>
        </div>
        <p className="text-cyber-muted font-mono text-sm">Cargando...</p>
      </div>
    </div>
  );
}

export function Routes() {
  return (
    <AnimatePresence mode="wait">
      <Suspense fallback={<PageLoader />}>
        <RouterRoutes>
          <Route path="/" element={<Index />} />
          <Route path="/about" element={<About />} />
          <Route path="/content" element={<Content />} />
          <Route path="/tags" element={<Tags />} />
          <Route path="/tags/:tagName" element={<TagPosts />} />
          <Route path="/post/:id" element={<Post />} />
          <Route path="*" element={<NotFound />} />
        </RouterRoutes>
      </Suspense>
    </AnimatePresence>
  );
}
