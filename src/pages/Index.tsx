import { motion } from 'framer-motion';
import { usePublishedPosts } from '@/hooks/use-posts';
import { PostCard } from '@/components/ui/post-card';
import { parseDateLocal } from '@/lib/date';
import { Sparkles } from 'lucide-react';

export function Index() {
  const posts = usePublishedPosts();

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="space-y-12"
    >
      {/* Publicaciones recientes */}
      <section>
        <div className="flex items-center gap-3 mb-8">
          <Sparkles className="text-cyber-primary h-6 w-6 animate-pulse" />
          <h2 className="text-4xl font-cyber font-bold text-cyber-text glow-text">
            Publicaciones recientes
          </h2>
        </div>
        
        <div className="readable-list grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6 auto-rows-fr">
          {posts.slice(0, 6).map((post, index) => (
            <motion.div
              key={post.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className="h-full"
            >
              <PostCard
                title={post.title}
                description={post.description}
                date={parseDateLocal(post.date).toLocaleDateString('es-ES', { day: 'numeric', month: 'short', year: 'numeric' })}
                readTime={post.readTime ?? ''}
                tags={post.tags}
                href={`/post/${post.id}`}
              />
            </motion.div>
          ))}
        </div>
      </section>
    </motion.div>
  );
}
