import React, { useState, useRef, useEffect } from 'react';
import { Search, X } from 'lucide-react';
import { useSearch } from '@/hooks/use-search';
import { SearchResults } from './search-results';
import { sanitizeSearchInput, searchRateLimiter } from '@/utils/sanitize';

interface SearchBarProps {
  placeholder?: string;
  onSearch?: (query: string) => void;
}

export function SearchBar({ placeholder = "BUSCAR EN EL SISTEMA...", onSearch }: SearchBarProps) {
  const [query, setQuery] = useState('');
  const [isFocused, setIsFocused] = useState(false);
  const searchContainerRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  
  const { results, isLoading } = useSearch(query);

  // Manejar clic fuera para cerrar resultados
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (searchContainerRef.current && !searchContainerRef.current.contains(event.target as Node)) {
        setIsFocused(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Manejar teclas de navegación y shortcut
  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsFocused(false);
        inputRef.current?.blur();
      }
      if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
        event.preventDefault();
        inputRef.current?.focus();
      }
    };

    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value;
    const sanitized = sanitizeSearchInput(raw);
    // Rate limit suave para prevenir abuso en cliente
    const allowed = searchRateLimiter.checkLimit('search', 60, 10000);
    if (!allowed) return;
    setQuery(sanitized);
    onSearch?.(sanitized);
  };

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (query.trim() && results.length > 0) {
      // Navegar al primer resultado
      window.location.href = `/post/${results[0].post.id}`;
      setIsFocused(false);
    }
  };

  const handleClear = () => {
    setQuery('');
    setIsFocused(false);
    inputRef.current?.focus();
  };

  return (
    <div ref={searchContainerRef} className="relative w-full max-w-xl">
      <form onSubmit={handleSubmit}>
        <div className="relative group">
          <Search className="absolute left-4 top-1/2 transform -translate-y-1/2 text-cyber-primary/70 h-5 w-5 transition-all group-hover:text-cyber-primary group-hover:drop-shadow-[0_0_5px_rgba(0,255,159,0.5)]" />
          <input
            ref={inputRef}
            type="search"
            value={query}
            onChange={handleInputChange}
            onFocus={() => setIsFocused(true)}
            placeholder={placeholder}
            className="w-full bg-black/40 border border-cyber-border/50 rounded-lg pl-12 pr-12 py-3
                     text-base text-cyber-text placeholder:text-cyber-muted/70 placeholder:font-mono focus:outline-none focus:border-cyber-primary
                     focus:ring-1 focus:ring-cyber-primary/50 backdrop-blur-md transition-all duration-300
                     hover:bg-black/60 hover:border-cyber-primary/70 shadow-inner font-mono text-sm tracking-wide"
          />
          
          {/* Shortcut hint or Clear button */}
          <div className="absolute right-3 top-1/2 transform -translate-y-1/2 flex items-center">
            {query ? (
              <button
                type="button"
                onClick={handleClear}
                className="text-cyber-muted hover:text-cyber-primary transition-colors p-1"
              >
                <X className="h-4 w-4" />
              </button>
            ) : (
              <div className="hidden md:flex items-center gap-1 text-[10px] text-cyber-muted border border-cyber-border/30 rounded px-1.5 py-0.5 font-mono">
                <span className="text-xs">⌘</span>
                <span>K</span>
              </div>
            )}
          </div>
          
          {/* Glow effect on focus */}
          <div className="absolute inset-0 rounded-lg bg-cyber-primary/5 opacity-0 group-hover:opacity-100 peer-focus:opacity-100 transition-opacity pointer-events-none"></div>
        </div>
      </form>

      {/* Resultados de búsqueda */}
      <div className="absolute top-full left-0 right-0 mt-2 z-50">
        <SearchResults 
          results={results} 
          isLoading={isLoading} 
          isVisible={isFocused && query.length > 0}
          onClose={() => setIsFocused(false)} 
          query={query}
        />
      </div>
    </div>
  );
}
