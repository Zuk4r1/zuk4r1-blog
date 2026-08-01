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

type RouteEntry = {
  path: string;
  element: ReactNode;
};

const routes: RouteEntry[] = [
  { path: '/', element: <Index /> },
  { path: '/about', element: <About /> },
  { path: '/content', element: <Content /> },
  { path: '/tags', element: <Tags /> },
  { path: '/tags/:tagName', element: <TagPosts /> },
  { path: '/post/:id', element: <Post /> },
  { path: '*', element: <NotFound /> },
];

function matchRoute(path: string) {
  const pathSegments = path === '/' ? [] : path.slice(1).split('/');
  const fallbackRoute = routes.find((route) => route.path === '*')!;

  for (const route of routes) {
    if (route.path === '*') {
      continue;
    }

    const routeSegments = route.path === '/' ? [] : route.path.slice(1).split('/');
    if (routeSegments.length !== pathSegments.length) {
      continue;
    }

    const params: Record<string, string> = {};
    let match = true;

    for (let index = 0; index < routeSegments.length; index += 1) {
      const routeSegment = routeSegments[index];
      const pathSegment = pathSegments[index];

      if (routeSegment.startsWith(':')) {
        params[routeSegment.slice(1)] = decodeURIComponent(pathSegment);
        continue;
      }

      if (routeSegment !== pathSegment) {
        match = false;
        break;
      }
    }

    if (match) {
      return { route, params };
    }
  }

  return { route: fallbackRoute, params: {} };
}

export { matchRoute };

export function Routes({ path }: { path: string }) {
  const { route } = matchRoute(path);

  return (
    <AnimatePresence mode="wait">
      <Suspense fallback={<PageLoader />}>
        <div key={path}>{route.element}</div>
      </Suspense>
    </AnimatePresence>
  );
}
