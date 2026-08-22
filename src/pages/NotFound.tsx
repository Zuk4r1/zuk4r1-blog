import { motion } from 'framer-motion';
import { Link } from '@/lib/router';
import { useSEO } from '@/hooks/use-seo';

export function NotFound() {
  useSEO({
    title: '404 - Página no encontrada',
    description: 'La página que buscas no existe o ha sido movida.',
    url: window.location.href,
    type: 'website',
  });

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="container mx-auto px-4 py-16 text-center"
    >
      <motion.h1
        initial={{ y: -20 }}
        animate={{ y: 0 }}
        className="text-6xl font-bold text-cyber-primary glow-text mb-4"
      >
        404
      </motion.h1>
      
      <motion.h2
        initial={{ y: -20 }}
        animate={{ y: 0 }}
        transition={{ delay: 0.1 }}
        className="text-2xl font-semibold text-cyber-text mb-6"
      >
        Página No Encontrada
      </motion.h2>
      
      <motion.p
        initial={{ y: -20 }}
        animate={{ y: 0 }}
        transition={{ delay: 0.2 }}
        className="text-cyber-muted mb-8"
      >
        La página que estás buscando no existe o ha sido movida.
      </motion.p>
      
      <motion.div
        initial={{ y: -20, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ delay: 0.3 }}
      >
        <Link
          to="/"
          className="inline-block px-6 py-3 bg-cyber-primary text-cyber-background font-bold rounded-lg hover:bg-cyber-primary/90 transition-colors"
        >
          Volver al Inicio
        </Link>
      </motion.div>
    </motion.div>
  );
}