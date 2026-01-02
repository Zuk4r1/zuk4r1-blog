import { Link } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { SearchResult } from '@/hooks/use-search';
import { Calendar, Clock, FileText, ChevronRight } from 'lucide-react';
import { parseDateLocal } from '@/lib/date';

interface SearchResultsProps {
  results: SearchResult[];
  isLoading: boolean;
  isVisible: boolean;
  onClose: () => void;
  query: string;
}

export function SearchResults({ results, isLoading, isVisible, onClose, query }: SearchResultsProps) {
  return (
    <AnimatePresence>
      {isVisible && (
        <motion.div
          initial={{ opacity: 0, y: -10, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -10, scale: 0.95 }}
          transition={{ duration: 0.2 }}
          className="bg-cyber-card/95 backdrop-blur-md border border-cyber-border rounded-lg shadow-2xl overflow-hidden max-h-[80vh] flex flex-col"
        >
          {/* Header de resultados */}
          <div className="p-3 border-b border-cyber-border/50 bg-cyber-primary/5 flex items-center justify-between sticky top-0 backdrop-blur-sm z-10">
            <h3 className="text-xs font-mono font-bold text-cyber-primary uppercase tracking-wider flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyber-primary animate-pulse"></span>
              Resultados: "{query}"
            </h3>
            <span className="text-[10px] text-cyber-muted font-mono">{results.length} ENCONTRADOS</span>
          </div>

          {/* Contenido de resultados */}
          <div className="overflow-y-auto custom-scrollbar p-2">
            {isLoading ? (
              <div className="flex flex-col items-center justify-center p-8 space-y-4">
                <div className="relative w-12 h-12">
                  <div className="absolute inset-0 border-t-2 border-cyber-primary rounded-full animate-spin"></div>
                  <div className="absolute inset-2 border-r-2 border-cyber-secondary rounded-full animate-spin-reverse"></div>
                </div>
                <span className="text-cyber-primary font-mono text-sm animate-pulse">ESCANEANDO BASE DE DATOS...</span>
              </div>
            ) : results.length === 0 ? (
              <div className="text-center p-8 flex flex-col items-center">
                <div className="w-16 h-16 bg-cyber-card rounded-full flex items-center justify-center border border-cyber-border mb-4">
                  <FileText className="h-8 w-8 text-cyber-muted" />
                </div>
                <p className="text-cyber-text font-bold mb-1">Sin coincidencias</p>
                <p className="text-xs text-cyber-muted max-w-[200px]">
                  No se encontraron datos que coincidan con los parámetros de búsqueda.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                {results.map((result, index) => (
                  <motion.div
                    key={result.post.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: index * 0.05 }}
                  >
                    <Link
                      to={`/post/${result.post.id}`}
                      onClick={onClose}
                      className="card block p-4 rounded-lg bg-cyber-card/40 border border-cyber-border/30 hover-elevate gpu-smooth
                               hover:bg-cyber-primary/10 hover:border-cyber-primary/50 transition-all duration-300 group relative overflow-hidden"
                    >
                      <div className="absolute left-0 top-0 bottom-0 w-1 bg-cyber-primary transform -translate-x-full group-hover:translate-x-0 transition-transform duration-300"></div>
                      
                      <div className="flex justify-between items-start gap-4">
                        <div className="flex-1 min-w-0">
                          {/* Título */}
                          <h4 className="font-cyber font-bold text-cyber-text group-hover:text-cyber-primary transition-colors mb-1 truncate">
                            {result.post.title}
                          </h4>

                          {/* Metadata */}
                          <div className="flex items-center gap-3 text-[10px] text-cyber-muted font-mono mb-2">
                            <div className="flex items-center gap-1">
                              <Calendar className="h-3 w-3" />
                              <span>{parseDateLocal(result.post.date).toLocaleDateString('es-ES')}</span>
                            </div>
                            {result.post.readTime && (
                              <div className="flex items-center gap-1">
                                <Clock className="h-3 w-3" />
                                <span>{result.post.readTime}</span>
                              </div>
                            )}
                          </div>

                          {/* Campos coincidentes */}
                          {result.matchedFields.length > 0 && (
                            <div className="flex items-center gap-2 mb-2">
                              {result.matchedFields.map((field) => (
                                <span key={field} className="chip-3d chip-3d-sm font-mono">
                                  {field}
                                </span>
                              ))}
                            </div>
                          )}

                          {/* Descripción */}
                          <p className="text-xs text-cyber-text/70 line-clamp-2">
                            {result.post.description}
                          </p>
                        </div>
                        
                        <ChevronRight className="h-5 w-5 text-cyber-muted group-hover:text-cyber-primary transform group-hover:translate-x-1 transition-all" />
                      </div>
                    </Link>
                  </motion.div>
                ))}
              </div>
            )}
          </div>
          
          {/* Footer */}
          <div className="p-2 border-t border-cyber-border/30 bg-black/20 text-[10px] text-center text-cyber-muted font-mono">
            PRESS <span className="text-cyber-primary">ENTER</span> TO SELECT
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
