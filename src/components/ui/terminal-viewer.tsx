import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { Copy, Check } from 'lucide-react';

interface TerminalViewerProps {
  code: string;
  language?: string;
  title?: string;
  showLineNumbers?: boolean;
}

export function TerminalViewer({ 
  code, 
  language = 'bash', 
  title = 'Terminal',
  showLineNumbers = false 
}: TerminalViewerProps) {
  const [displayCode, setDisplayCode] = useState('');
  const [isCopied, setIsCopied] = useState(false);
  const [isAnimating, setIsAnimating] = useState(true);

  // Efecto de typing
  useEffect(() => {
    if (!isAnimating) {
      setDisplayCode(code);
      return;
    }

    setDisplayCode('');
    let index = 0;

    const interval = setInterval(() => {
      if (index < code.length) {
        setDisplayCode(code.substring(0, index + 1));
        index++;
      } else {
        setIsAnimating(false);
        clearInterval(interval);
      }
    }, 20); // Velocidad de typing

    return () => clearInterval(interval);
  }, [code, isAnimating]);

  const handleCopy = () => {
    navigator.clipboard.writeText(code);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  const lines = displayCode.split('\n');

  return (
    <motion.div
      className="my-6 rounded-lg overflow-hidden border border-cyber-primary/30 bg-black/80 backdrop-blur-md"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      {/* Header del Terminal */}
      <motion.div
        className="bg-cyber-primary/10 border-b border-cyber-primary/30 px-4 py-3 flex items-center justify-between"
        animate={{
          boxShadow: [
            '0 0 0px rgba(0, 255, 159, 0)',
            '0 4px 12px rgba(0, 255, 159, 0.1)',
            '0 0 0px rgba(0, 255, 159, 0)',
          ],
        }}
        transition={{ duration: 2, repeat: Infinity }}
      >
        <div className="flex items-center gap-2">
          <div className="flex gap-1">
            <div className="w-2 h-2 rounded-full bg-cyber-primary/40" />
            <div className="w-2 h-2 rounded-full bg-cyber-primary/40" />
            <div className="w-2 h-2 rounded-full bg-cyber-primary/40" />
          </div>
          <span className="text-xs font-mono text-cyber-primary uppercase tracking-widest ml-2">
            {title}
          </span>
          <span className="text-xs text-cyber-muted ml-auto">{language}</span>
        </div>
        <motion.button
          onClick={handleCopy}
          className="text-cyber-muted hover:text-cyber-primary transition-colors p-1"
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.95 }}
        >
          {isCopied ? (
            <Check className="h-4 w-4 text-cyber-primary" />
          ) : (
            <Copy className="h-4 w-4" />
          )}
        </motion.button>
      </motion.div>

      {/* Contenido del código */}
      <div className="p-4 font-mono text-sm overflow-x-auto">
        <div className="space-y-0">
          {lines.map((line, index) => (
            <div key={index} className="flex items-start gap-4">
              {showLineNumbers && (
                <span className="text-cyber-muted/50 select-none min-w-[2rem] text-right">
                  {index + 1}
                </span>
              )}
              <motion.code
                className="text-cyber-secondary flex-1"
                initial={isAnimating ? { opacity: 0 } : { opacity: 1 }}
                animate={{ opacity: 1 }}
                transition={{ delay: index * 0.02 }}
              >
                {line || '\u00A0'}
              </motion.code>
            </div>
          ))}

          {/* Cursor parpadeante */}
          {isAnimating && displayCode.length > 0 && (
            <motion.div
              className="inline-block w-2 h-5 bg-cyber-primary ml-1"
              animate={{ opacity: [1, 0] }}
              transition={{ duration: 0.6, repeat: Infinity }}
            />
          )}
        </div>
      </div>

      {/* Footer con efecto de línea */}
      <motion.div
        className="h-px bg-gradient-to-r from-transparent via-cyber-primary to-transparent opacity-30"
        animate={{
          opacity: [0.1, 0.5, 0.1],
        }}
        transition={{ duration: 2, repeat: Infinity }}
      />
    </motion.div>
  );
}
