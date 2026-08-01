import React, { createContext, useContext, useMemo, type AnchorHTMLAttributes, type ReactNode } from 'react';

interface RouterContextValue {
  path: string;
  params: Record<string, string>;
  navigate: (to: string, replace?: boolean) => void;
}

const RouterContext = createContext<RouterContextValue | null>(null);

function normalizePath(href: string) {
  try {
    const url = new URL(href, window.location.origin);
    const pathname = url.pathname.replace(/\/+$/g, '');
    return pathname === '' ? '/' : pathname;
  } catch {
    return '/';
  }
}

export function useRouter() {
  const context = useContext(RouterContext);
  if (!context) {
    throw new Error('useRouter must be used within a RouterProvider');
  }
  return context;
}

export function useNavigate() {
  return useRouter().navigate;
}

export function useParams<T extends Record<string, string> = Record<string, string>>() {
  return useRouter().params as T;
}

export function RouterProvider({
  children,
  path,
  params,
  navigate,
}: {
  children: ReactNode;
  path: string;
  params: Record<string, string>;
  navigate: (to: string, replace?: boolean) => void;
}) {
  const value = useMemo(
    () => ({ path, params, navigate }),
    [path, params, navigate],
  );

  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

function isExternalLink(href: string) {
  return /^https?:\/\//i.test(href) || href.startsWith('mailto:');
}

export function Link({
  to,
  replace = false,
  children,
  onClick,
  ...props
}: {
  to: string;
  replace?: boolean;
  children: ReactNode;
} & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'>) {
  const { navigate, path } = useRouter();
  const normalized = normalizePath(to);
  const isExternal = isExternalLink(to);

  const handleClick = (event: React.MouseEvent<HTMLAnchorElement>) => {
    onClick?.(event);
    if (event.defaultPrevented) {
      return;
    }

    if (isExternal || to.startsWith('#')) {
      return;
    }

    event.preventDefault();
    if (normalized !== path) {
      navigate(normalized, replace);
    }
  };

  return (
    <a
      href={to}
      target={isExternal ? '_blank' : undefined}
      rel={isExternal ? 'noopener noreferrer' : undefined}
      onClick={handleClick}
      {...props}
    >
      {children}
    </a>
  );
}

export function NavLink({
  to,
  exact = false,
  activeClassName = '',
  className = '',
  children,
  ...props
}: {
  to: string;
  exact?: boolean;
  activeClassName?: string;
  className?: string;
  children: ReactNode;
} & Omit<AnchorHTMLAttributes<HTMLAnchorElement>, 'href'>) {
  const { path, navigate } = useRouter();
  const normalizedTo = normalizePath(to);
  const isActive = normalizedTo === '/'
    ? path === '/'
    : exact
    ? path === normalizedTo
    : path === normalizedTo || path.startsWith(`${normalizedTo}/`);

  const handleClick = (event: React.MouseEvent<HTMLAnchorElement>) => {
    if (event.defaultPrevented) {
      return;
    }
    event.preventDefault();
    if (path !== normalizedTo) {
      navigate(normalizedTo);
    }
  };

  return (
    <a
      href={to}
      className={`${className} ${isActive ? activeClassName : ''}`.trim()}
      onClick={handleClick}
      {...props}
    >
      {children}
    </a>
  );
}

export function createRouterNavigate() {
  const { navigate } = useRouter();
  return navigate;
}

export { normalizePath };
