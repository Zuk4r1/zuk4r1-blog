import { Link } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Clock, Calendar, ArrowRight } from 'lucide-react';

interface PostCardProps {
  title: string;
  description: string;
  date: string;
  readTime: string;
  tags: string[];
  href: string;
}

export function PostCard({ title, description, date, readTime, tags, href }: PostCardProps) {
  return (
    <motion.article
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -10, scale: 1.02 }}
      transition={{ type: "spring", stiffness: 300, damping: 20 }}
      className="group relative h-full"
    >
      <Link to={href} className="block h-full hover-elevate gpu-smooth">
        <div className="card relative h-full overflow-hidden rounded-xl border border-cyber-border/50 bg-cyber-card/40 backdrop-blur-md 
                        transition-all duration-500 group-hover:border-cyber-primary/50 depth-card transform-gpu
                        flex flex-col">
          
          {/* Decorative elements */}
          <div className="absolute top-0 right-0 p-3 opacity-50 group-hover:opacity-100 transition-opacity">
            <div className="flex gap-1">
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-primary/30 group-hover:bg-cyber-primary"></div>
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-primary/30 group-hover:bg-cyber-primary delay-75"></div>
              <div className="w-1.5 h-1.5 rounded-full bg-cyber-primary/30 group-hover:bg-cyber-primary delay-150"></div>
            </div>
          </div>
          
          {/* Corner accents */}
          <div className="absolute top-0 left-0 w-8 h-8 border-t-2 border-l-2 border-cyber-primary/0 group-hover:border-cyber-primary/50 rounded-tl-xl transition-all duration-500"></div>
          <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-cyber-primary/0 group-hover:border-cyber-primary/50 rounded-br-xl transition-all duration-500"></div>

          {/* Glow effect on hover */}
          <div className="absolute inset-0 bg-gradient-to-br from-cyber-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-all duration-500 pointer-events-none" />
          
          <div className="p-6 flex flex-col flex-grow z-10">
            <div className="mb-4">
              <div className="flex flex-wrap gap-2 mb-3">
                {tags.map((tag) => (
                  <span
                    key={tag}
                    className="chip-3d chip-3d-sm font-mono"
                  >
                    {tag}
                  </span>
                ))}
              </div>
              
              <h2 className="text-xl md:text-2xl font-cyber font-semibold text-white glow-text 
                           transition-colors duration-300 mb-3 leading-tight">
                {title}
              </h2>
            </div>
            
            <p className="text-white/60 text-sm leading-relaxed mb-6 line-clamp-3 transition-colors duration-300 flex-grow">
              {description}
            </p>
            
            <div className="mt-auto pt-4 border-t border-cyber-border/30 flex items-center justify-between text-xs font-mono text-cyber-muted">
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-1.5 group-hover:text-cyber-primary/80 transition-colors">
                  <Calendar className="h-3.5 w-3.5" />
                  <span>{date}</span>
                </div>
                <div className="flex items-center gap-1.5 group-hover:text-cyber-primary/80 transition-colors">
                  <Clock className="h-3.5 w-3.5" />
                  <span>{readTime}</span>
                </div>
              </div>
              
              <div className="transform translate-x-[-10px] opacity-0 group-hover:translate-x-0 group-hover:opacity-100 transition-all duration-300 text-cyber-primary flex items-center gap-1">
                <span>LEER</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </div>
            </div>
          </div>
        </div>
      </Link>
    </motion.article>
  );
}
