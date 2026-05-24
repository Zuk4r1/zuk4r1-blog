import { useState } from 'react';
import { motion } from 'framer-motion';
import { Maximize2, Minimize2 } from 'lucide-react';

interface FullscreenReaderProps {
  content: React.ReactNode;
}

export function FullscreenReader({ content }: FullscreenReaderProps) {
  const [isFullscreen, setIsFullscreen] = useState(false);

  const toggleFullscreen = () => {
    setIsFullscreen(!isFullscreen);
  };

  return (
    <>
      {/* Botón para activar fullscreen */}
      <motion.button
        onClick={toggleFullscreen}
        className="fixed bottom-6 right-6 z-30 bg-cyber-card/90 border-2 border-cyber-primary/60 rounded-lg p-3 text-cyber-primary hover:shadow-neon-strong transition-all duration-300"
        whileHover={{ scale: 1.1 }}
        whileTap={{ scale: 0.95 }}
        title={isFullscreen ? 'Salir del modo lectura' : 'Modo lectura fullscreen'}
      >
        {isFullscreen ? (
          <Minimize2 className="h-5 w-5" />
        ) : (
          <Maximize2 className="h-5 w-5" />
        )}
      </motion.button>

      {/* Modo fullscreen */}
      {isFullscreen && (
        <motion.div
          className="fixed inset-0 bg-black z-[999] overflow-y-auto"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.3 }}
        >
          {/* Overlay de escaneo */}
          <div
            className="fixed inset-0 pointer-events-none opacity-5 z-[1000]"
            style={{
              backgroundImage: 'linear-gradient(0deg, transparent 0%, rgba(0, 255, 159, 0.03) 50%, transparent 100%)',
              backgroundSize: '100% 4px',
              animation: 'scanline 8s linear infinite',
            }}
          />

          {/* Contenido */}
          <div className="relative z-10 max-w-4xl mx-auto px-6 py-12">
            <motion.div
              className="readable prose-invert"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
            >
              {content}
            </motion.div>

            {/* Indicador de modo fullscreen */}
            <motion.div
              className="fixed top-4 left-4 flex items-center gap-2 bg-cyber-card/90 border border-cyber-primary/50 rounded-lg px-4 py-2 z-[1001]"
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.2 }}
            >
              <div className="w-2 h-2 bg-cyber-primary rounded-full animate-pulse" />
              <span className="text-xs font-mono text-cyber-primary uppercase tracking-widest">
                Modo Terminal
              </span>
            </motion.div>

            {/* Botón para salir */}
            <motion.button
              onClick={toggleFullscreen}
              className="fixed bottom-6 right-6 bg-cyber-card/90 border-2 border-cyber-primary/60 rounded-lg p-3 text-cyber-primary hover:shadow-neon-strong transition-all duration-300 z-[1001]"
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.95 }}
            >
              <Minimize2 className="h-5 w-5" />
            </motion.button>
          </div>
        </motion.div>
      )}
    </>
  );
}
