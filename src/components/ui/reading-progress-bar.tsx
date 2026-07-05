import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';

interface ReadingProgressBarProps {
  postLength: number; // longitud del contenido en caracteres
}

export function ReadingProgressBar({ postLength }: ReadingProgressBarProps) {
  const [progress, setProgress] = useState(0);
  const [readingTime, setReadingTime] = useState('0 min');

  useEffect(() => {
    const handleScroll = () => {
      const scrollHeight = document.documentElement.scrollHeight - window.innerHeight;
      const scrolled = window.scrollY;
      const scrollPercent = scrollHeight > 0 ? (scrolled / scrollHeight) * 100 : 0;
      setProgress(Math.min(100, scrollPercent));

      // Calcular tiempo estimado de lectura restante
      const wordsPerMinute = 200;
      const words = postLength / 5; // aproximadamente
      const totalReadTime = Math.ceil(words / wordsPerMinute);
      const estimatedRemaining = Math.max(0, totalReadTime - Math.ceil((progress / 100) * totalReadTime));
      setReadingTime(estimatedRemaining > 0 ? `${estimatedRemaining} min` : 'Finalizado');
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [postLength, progress]);

  return (
    <div className="fixed top-0 left-0 right-0 z-50">
      {/* Barra de progreso */}
      <motion.div
        className="h-1 bg-gradient-to-r from-cyber-primary via-cyber-secondary to-cyber-accent shadow-neon-strong"
        style={{
          width: `${progress}%`,
        }}
        transition={{ duration: 0.2 }}
      />

      {/* Indicador de progreso */}
      {progress > 0 && (
        <motion.div
          className="fixed top-4 right-4 bg-cyber-card/90 backdrop-blur-md border border-cyber-primary/50 rounded-lg px-4 py-2 z-50"
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
        >
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 flex items-center justify-center">
              <motion.div
                className="w-full h-full rounded border-2 border-cyber-primary/30 flex items-center justify-center text-xs font-mono text-cyber-primary"
                animate={{ boxShadow: [
                  '0 0 5px rgba(0, 255, 159, 0.3)',
                  '0 0 15px rgba(0, 255, 159, 0.6)',
                  '0 0 5px rgba(0, 255, 159, 0.3)',
                ] }}
                transition={{ duration: 2, repeat: Infinity }}
              >
                {Math.round(progress)}%
              </motion.div>
            </div>
            <span className="text-xs font-mono text-cyber-text whitespace-nowrap">
              {readingTime}
            </span>
          </div>
        </motion.div>
      )}
    </div>
  );
}
