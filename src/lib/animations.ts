/**
 * Constantes de animación reutilizables con Framer Motion
 * Consolida la lógica duplicada de animaciones en un único lugar
 */

export const glowAnimationVariants = {
  container: {
    animate: {
      boxShadow: [
        '0 0 0px rgba(0, 255, 159, 0)',
        '0 4px 12px rgba(0, 255, 159, 0.1)',
        '0 0 0px rgba(0, 255, 159, 0)',
      ],
    },
    transition: { duration: 2, repeat: Infinity }
  }
};

export const pulseScale = {
  animate: {
    scale: [1, 1.2, 1],
  },
  transition: {
    duration: 0.6,
    delay: 0.3,
  }
};

export const fadeInScale = {
  initial: { opacity: 0, scale: 0.95 },
  animate: { opacity: 1, scale: 1 },
  exit: { opacity: 0, scale: 0.95 },
  transition: { duration: 0.2 }
};

export const fadeIn = {
  initial: { opacity: 0 },
  animate: { opacity: 1 },
  transition: { duration: 0.5 }
};

export const slideUp = {
  initial: { opacity: 0, y: 20 },
  animate: { opacity: 1, y: 0 },
};

export const staggerContainer = {
  animate: {
    transition: {
      staggerChildren: 0.1,
    },
  },
};
