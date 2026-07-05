import React, { useCallback } from 'react';
import { motion } from 'framer-motion';
import { useParams, Link } from 'react-router-dom';
import { getPostsByTag, Post as PostType } from '@/lib/posts';
import { usePostsSubscription } from '@/hooks/use-posts';
import { sanitizeTag } from '@/utils/sanitize';
import { PostCard } from '@/components/ui/post-card';
import { formatPostDate } from '@/lib/date';
import { ArrowLeft } from 'lucide-react';

export function TagPosts() {
  const { tagName } = useParams<{ tagName: string }>();
  const [posts, setPosts] = React.useState<PostType[]>([]);

  React.useEffect(() => {
    if (tagName) {
      const safeTag = sanitizeTag(tagName).toLowerCase();
      getPostsByTag(safeTag).then(setPosts);
    }
  }, [tagName]);

  // Suscribirse a cambios de posts en desarrollo (HMR) para reflejar altas/bajas
  const handlePostsUpdate = useCallback((updated: PostType[]) => {
    if (tagName) {
      const safeTag = sanitizeTag(tagName).toLowerCase();
      setPosts(updated.filter((p) => p.published && p.tags.includes(safeTag)));
    }
  }, [tagName]);

  usePostsSubscription(handlePostsUpdate);

  if (!tagName) {
    return (
      <div className="container mx-auto px-4 py-8">
        <p className="text-center text-muted-foreground">Etiqueta no especificada.</p>
      </div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      transition={{ duration: 0.5 }}
      className="container mx-auto px-4 py-8"
    >
      {/* Header */}
      <div className="mb-8">
        <Link
          to="/tags"
          className="inline-flex items-center gap-2 text-cyber-primary hover:text-cyber-primary/80 transition-colors mb-4"
        >
          <ArrowLeft className="h-4 w-4" />
          Volver a etiquetas
        </Link>
        
        <h1 className="text-4xl font-bold text-cyber-primary mb-2">
          Publicaciones con etiqueta: <span className="text-cyber-primary">{sanitizeTag(tagName)}</span>
        </h1>
        
        <p className="text-muted-foreground">
          {posts.length} {posts.length === 1 ? 'publicación encontrada' : 'publicaciones encontradas'}
        </p>
      </div>

      {/* Posts Grid */}
      {posts.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {posts.map((post) => (
            <PostCard
              key={post.id}
              title={post.title}
              description={post.description}
              date={formatPostDate(post.date)}
              readTime={post.readTime || '5 min'}
              tags={post.tags}
              href={`/post/${post.id}`}
            />
          ))}
        </div>
      ) : (
        <div className="text-center py-16">
          <p className="text-muted-foreground text-lg mb-4">
            No se encontraron publicaciones con la etiqueta "{tagName}".
          </p>
          <Link
            to="/tags"
            className="inline-block px-6 py-3 border border-cyber-primary text-cyber-primary rounded-lg hover:bg-cyber-primary/10 transition-colors"
          >
            Ver todas las etiquetas
          </Link>
        </div>
      )}
    </motion.div>
  );
}
