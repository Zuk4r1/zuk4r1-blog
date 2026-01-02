import { NavLink } from 'react-router-dom';
import { Home, Tags, FileText, User, Github, Mail, Linkedin, X } from 'lucide-react';
import perfil from '@/assets/perfil.png';

// Icono personalizado de Discord
function DiscordIcon({ className = "" }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      className={className}
      fill="currentColor"
      role="img"
      aria-hidden="true"
    >
      <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
    </svg>
  );
}

const navigation = [
  { name: "Inicio", icon: Home, href: "/" },
  { name: "Etiquetas", icon: Tags, href: "/tags" },
  { name: "Contenido", icon: FileText, href: "/content" },
  { name: "Acerca de", icon: User, href: "/about" },
];

const socialLinks = [
  { name: "GitHub", icon: Github, href: "https://github.com/Zuk4r1" },
  { name: "Email", icon: Mail, href: "mailto:investigacion1956@gmail.com" },
  { name: "LinkedIn", icon: Linkedin, href: "https://www.linkedin.com/in/yordan-antonio-suarez-rojas-49706326b/" },
  { name: "Discord", icon: DiscordIcon, href: "https://discord.com/channels/zuk4r1" },
];

export function Sidebar() {
  return (
    <aside className="hidden md:flex md:fixed md:left-0 md:top-0 md:bottom-0 md:w-64 glass-panel panel-float panel-hardware
                       border-r border-cyber-border flex-col overflow-hidden z-40">
      {/* Contenedor scrollable interno */}
      <div className="flex-1 overflow-y-auto scrollbar-hide">
        {/* Logo y perfil */}
        <div className="p-5 text-center border-b border-cyber-border/30">
          <img
            src={perfil}
            alt="Perfil"
            className="w-24 h-24 mx-auto rounded-full border-2 border-cyber-primary mb-3 avatar-glow transition-transform duration-300 hover:scale-110"
          />
          <h1 className="text-lg font-cyber font-bold text-cyber-primary glow-text mb-3">Zuk4r1</h1>
          <p className="text-sm text-white px-3 glow-text">
            Donde la curiosidad impulsa la seguridad.
          </p>
        </div>

        {/* Navegación */}
        <nav className="p-6">
          <ul className="space-y-4">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <li key={item.name}>
                  <NavLink
                    to={item.href}
                    className={({ isActive }) =>
                      `flex items-center gap-4 px-4 py-3 rounded-lg transition-all duration-300 relative overflow-hidden group `
                        + (isActive
                          ? 'text-cyber-primary border border-cyber-primary/40 bg-cyber-primary/10 shadow-[0_0_12px_rgba(0,255,159,0.15)] translate-x-1'
                          : 'text-cyber-text hover:text-cyber-primary hover:bg-cyber-primary/5 hover:translate-x-1 hover:border hover:border-cyber-primary/20')
                    }
                  >
                    <div className="absolute left-0 top-0 bottom-0 w-0.5 bg-cyber-primary opacity-0 transition-all duration-300 group-hover:opacity-100 group-[.active]:opacity-100"></div>
                    <Icon className="h-5 w-5 transition-transform duration-300 group-hover:scale-110" />
                    <span className="font-mono text-sm tracking-wide font-bold uppercase">{item.name}</span>
                  </NavLink>
                </li>
              );
            })}
          </ul>
        </nav>
      </div>

      {/* Redes sociales */}
      <div className="p-6 border-t border-cyber-border/30 bg-black/20">
        <p className="text-center text-white text-xs uppercase tracking-[0.2em] mb-4 font-cyber">Conectar</p>
        <div className="flex justify-center gap-3 mb-6">
          {socialLinks.map((link) => {
            const Icon = link.icon;
            return (
              <a
                key={link.name}
                href={link.href}
                target="_blank"
                rel="noopener noreferrer"
                className="w-10 h-10 flex items-center justify-center rounded-lg bg-cyber-card border border-cyber-border/50 
                           shadow-lg hover:shadow-neon hover:border-cyber-primary hover:-translate-y-1 transition-all duration-300 group"
                aria-label={link.name}
              >
                <Icon className="h-5 w-5 text-cyber-muted group-hover:text-cyber-primary transition-colors duration-300" />
              </a>
            );
          })}
        </div>

        {/* Copyright */}
        <div className="text-center text-xs text-white/80 font-mono tracking-wide">
          <p>©2026–2027 Zuk4r1</p>
          <p>Derechos reservados</p>
        </div>
      </div>
    </aside>
  );
}

export function SidebarOverlay({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 md:hidden backdrop-blur-sm">
      <div className="absolute inset-0 bg-black/60 transition-opacity" onClick={onClose} />
      <aside className="absolute left-0 top-0 bottom-0 w-72 glass-panel border-r border-cyber-border flex flex-col overflow-hidden animate-slide-in-left shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-cyber-border/30 bg-cyber-primary/5">
          <h2 className="text-sm font-cyber text-cyber-primary tracking-widest uppercase">Sistema</h2>
          <button onClick={onClose} className="text-cyber-muted hover:text-cyber-primary transition-colors p-2 hover:bg-cyber-primary/10 rounded-md">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          <div className="p-8 text-center border-b border-cyber-border/30 relative">
            <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-transparent via-cyber-primary to-transparent opacity-50"></div>
            <img src={perfil} alt="Perfil" className="w-24 h-24 mx-auto rounded-full border-2 border-cyber-primary mb-4 avatar-glow" />
            <h1 className="text-lg font-cyber text-cyber-primary glow-text mb-2">Zuk4r1</h1>
            <p className="text-xs text-cyber-text/70 font-mono">&lt;SecurityResearcher /&gt;</p>
          </div>
          <nav className="p-6">
            <ul className="space-y-4">
              {navigation.map((item) => {
                const Icon = item.icon;
                return (
                  <li key={item.name}>
                    <NavLink
                      to={item.href}
                      className={({ isActive }) =>
                        `flex items-center gap-4 px-4 py-3 rounded-lg transition-all duration-200 border ` +
                        (isActive
                          ? 'bg-cyber-primary/10 text-cyber-primary border-cyber-primary/40 shadow-neon-sm'
                          : 'border-transparent text-cyber-text hover:bg-cyber-primary/5 hover:text-cyber-primary hover:border-cyber-primary/20')
                      }
                      onClick={onClose}
                    >
                      <Icon className="h-5 w-5" />
                      <span className="font-mono text-sm uppercase font-bold">{item.name}</span>
                    </NavLink>
                  </li>
                );
              })}
            </ul>
          </nav>
        </div>
        <div className="p-6 border-t border-cyber-border/30 bg-black/20">
            <div className="flex justify-center gap-4">
            {socialLinks.map((link) => {
              const Icon = link.icon;
              return (
                <a
                  key={link.name}
                  href={link.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-10 h-10 flex items-center justify-center rounded-lg bg-cyber-card border border-cyber-border 
                             hover:border-cyber-primary hover:text-cyber-primary hover:shadow-neon transition-all duration-300"
                >
                  <Icon className="h-5 w-5" />
                </a>
              );
            })}
          </div>
        </div>
      </aside>
    </div>
  );
}
