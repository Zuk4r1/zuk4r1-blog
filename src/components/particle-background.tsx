import { useEffect, useRef } from 'react';

export function ParticleBackground() {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    // Crear partículas binarias aleatorias
    const createParticle = () => {
      const particle = document.createElement('div');
      const chars = ['0', '1', '█', '▓', '░', '▕', '▐'];
      const char = chars[Math.floor(Math.random() * chars.length)];
      
      particle.textContent = char;
      particle.className = 'particle';
      particle.style.left = Math.random() * 100 + '%';
      particle.style.top = '-20px';
      particle.style.fontSize = Math.random() * 10 + 8 + 'px';
      particle.style.opacity = Math.random() * 0.6 + 0.2 + '';
      particle.style.color = `hsl(${Math.random() > 0.7 ? 180 : 130}deg, 100%, 50%)`;
      
      // Variables CSS para animación
      const tx = (Math.random() - 0.5) * 200;
      const ty = Math.random() * 200 + 100;
      particle.style.setProperty('--tx', `${tx}px`);
      particle.style.setProperty('--ty', `${ty}px`);
      
      container.appendChild(particle);

      // Remover después de la animación
      setTimeout(() => particle.remove(), 3000);
    };

    // Crear partículas en intervalos
    const particleInterval = setInterval(createParticle, 300);

    return () => clearInterval(particleInterval);
  }, []);

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 pointer-events-none overflow-hidden"
      style={{ zIndex: 1 }}
    />
  );
}
