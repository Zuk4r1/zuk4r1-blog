import { useEffect, useRef } from 'react';

const MAX_PARTICLES = 48;

export function ParticleBackground() {
  const containerRef = useRef<HTMLDivElement>(null);
  const particleTimeouts = useRef<number[]>([]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const createParticle = () => {
      if (container.childElementCount >= MAX_PARTICLES) {
        const oldest = container.firstElementChild;
        if (oldest) {
          oldest.remove();
        }
      }

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

      const tx = (Math.random() - 0.5) * 180;
      const ty = Math.random() * 180 + 100;
      particle.style.setProperty('--tx', `${tx}px`);
      particle.style.setProperty('--ty', `${ty}px`);

      container.appendChild(particle);

      const timeoutId = window.setTimeout(() => particle.remove(), 3000);
      particleTimeouts.current.push(timeoutId);
    };

    const particleInterval = window.setInterval(createParticle, 180);

    return () => {
      window.clearInterval(particleInterval);
      particleTimeouts.current.forEach((timeoutId) => window.clearTimeout(timeoutId));
      particleTimeouts.current = [];
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="fixed inset-0 pointer-events-none overflow-hidden"
      style={{ zIndex: 1 }}
    />
  );
}
