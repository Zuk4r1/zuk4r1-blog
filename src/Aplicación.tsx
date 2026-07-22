import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import { Toaster } from 'sonner';
import { ThemeProvider } from '@/components/theme-provider';
import { Sidebar, SidebarOverlay } from '@/components/ui/sidebar';
import { SearchBar } from '@/components/ui/search-bar';
import { Routes } from '@/routes';
import { Menu } from 'lucide-react';

export default function Aplicación() {
  const handleSearch = (query: string) => {
    console.log('Buscando:', query);
  };
  const [open, setOpen] = React.useState(false);
  const headerRef = React.useRef<HTMLElement | null>(null);

  // Ajusta la variable CSS --site-header-height con la altura real del header
  React.useEffect(() => {
    const setHeaderHeight = () => {
      const el = headerRef.current;
      const height = el ? Math.ceil(el.getBoundingClientRect().height) : 80;
      document.documentElement.style.setProperty('--site-header-height', `${height}px`);
    };

    setHeaderHeight();

    // ResizeObserver para cambios dinámicos en el header (por ejemplo menú apilado)
    let ro: ResizeObserver | null = null;
    if (headerRef.current && (window as any).ResizeObserver) {
      ro = new (window as any).ResizeObserver(() => setHeaderHeight());
      ro.observe(headerRef.current);
    }

    window.addEventListener('resize', setHeaderHeight);
    return () => {
      window.removeEventListener('resize', setHeaderHeight);
      if (ro && headerRef.current) ro.unobserve(headerRef.current);
    };
  }, [open]);

  return (
    <BrowserRouter>
      <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
          <div className="min-h-screen bg-cyber-background text-cyber-text relative overflow-x-hidden selection:bg-cyber-primary/30 selection:text-cyber-primary">
            
            {/* Scanline Effect */}
            <div className="scanline-overlay"></div>
            
            {/* Background Gradients (Enhanced) */}
            <div className="fixed inset-0 pointer-events-none z-0">
               <div className="absolute top-[-10%] left-[-10%] w-[40%] h-[40%] bg-cyber-primary/5 rounded-full blur-[120px]"></div>
               <div className="absolute bottom-[-10%] right-[-10%] w-[40%] h-[40%] bg-cyber-secondary/5 rounded-full blur-[120px]"></div>
            </div>

            {/* Header con Logo y Búsqueda (adaptable a móviles) */}
            <header ref={headerRef} className="site-header fixed top-0 md:left-64 left-0 right-0 z-40 bg-cyber-background/80 backdrop-blur-md border-b border-cyber-border/40 transition-all duration-300 gpu-smooth">
              <div className="w-full px-4 py-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between max-w-7xl mx-auto">
                <div className="flex items-center gap-3">
                  <button 
                    className="md:hidden inline-flex items-center justify-center w-10 h-10 rounded-lg border border-cyber-border bg-cyber-card/60 text-cyber-text hover:bg-cyber-primary/20 hover:text-cyber-primary hover:border-cyber-primary/50 transition-all duration-300" 
                    onClick={() => setOpen(true)} 
                    aria-label="Abrir menú"
                  >
                    <Menu className="h-5 w-5" />
                  </button>
                  <h1 className="text-cyber-primary text-3xl sm:text-4xl font-extrabold font-cyber glow-text tracking-widest uppercase leading-none">
                    Cyber-Blog
                  </h1>
                  {/* Título de sección dinámico o breadcrumbs podrían ir aquí en desktop */}
                </div>
                <div className="w-full sm:max-w-md">
                  <SearchBar onSearch={handleSearch} />
                </div>
              </div>
            </header>

            {/* Layout Principal */}
            <div className="flex site-main relative z-10">
              {/* Sidebar (oculto en móviles) */}
              <Sidebar />

              {/* Contenido Principal */}
              <main className="flex-1 px-4 md:px-8 py-6 md:py-8 ml-0 md:ml-64 min-h-[calc(100vh-80px)] transition-all duration-300 gpu-smooth">
                <div className="max-w-7xl mx-auto animate-fade-in">
                  <Routes />
                </div>
              </main>
            </div>
            {open && <SidebarOverlay onClose={() => setOpen(false)} />}
          </div>
          <Toaster position="top-right" theme="dark" toastOptions={{
            style: {
              background: 'rgba(5, 5, 5, 0.9)',
              border: '1px solid rgba(0, 255, 159, 0.3)',
              color: '#e0e0e0',
              backdropFilter: 'blur(8px)',
            },
            className: 'font-mono'
          }} />
        </ThemeProvider>
      </BrowserRouter>
  );
}
