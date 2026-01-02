import React from 'react';
import { motion } from 'framer-motion';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { getPostById, Post as PostType } from '@/lib/posts';
import { NotFound } from './NotFound';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeSanitize, { defaultSchema } from 'rehype-sanitize';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { Calendar, Clock, ArrowLeft, Terminal } from 'lucide-react';
import { parseDateLocal } from '@/lib/date';

export function Post() {
  const { id } = useParams<{ id: string }>();
  const [post, setPost] = React.useState<PostType | null>(null);
  const [loading, setLoading] = React.useState(true);
  const navigate = useNavigate();

  React.useEffect(() => {
    if (id) {
      const isValid = /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id) && id.length <= 200;
      if (!isValid) {
        setPost(null);
        setLoading(false);
        return;
      }
      getPostById(id).then((foundPost) => {
        setPost(foundPost ?? null);
        setLoading(false);
      });
    }
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-6">
        <div className="relative w-24 h-24">
          <div className="absolute inset-0 border-t-4 border-cyber-primary rounded-full animate-spin"></div>
          <div className="absolute inset-4 border-r-4 border-cyber-secondary rounded-full animate-spin-reverse"></div>
          <div className="absolute inset-0 flex items-center justify-center">
            <Terminal className="h-8 w-8 text-cyber-primary animate-pulse" />
          </div>
        </div>
        <div className="font-mono text-cyber-primary text-xl animate-pulse">
          DECRYPTING CONTENT...
        </div>
      </div>
    );
  }

  if (!post) {
    return <NotFound />;
  }

  return (
    <motion.article
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="max-w-4xl mx-auto"
    >
      {/* Back button */}
      <Link 
        to="/" 
        className="inline-flex items-center gap-2 text-cyber-muted hover:text-cyber-primary transition-colors mb-8 group"
      >
        <ArrowLeft className="h-4 w-4 transform group-hover:-translate-x-1 transition-transform" />
        <span className="font-mono text-sm uppercase">Return to Base</span>
      </Link>

      {/* Main Content Card */}
      <div className="glass-panel rounded-xl overflow-hidden p-6 md:p-10 relative">
        {/* Header Background Decoration */}
        <div className="absolute top-0 right-0 p-4 opacity-30">
           <div className="flex gap-2">
             <div className="w-2 h-2 bg-cyber-primary rounded-full animate-pulse"></div>
             <div className="w-2 h-2 bg-cyber-secondary rounded-full animate-pulse delay-75"></div>
             <div className="w-2 h-2 bg-cyber-accent rounded-full animate-pulse delay-150"></div>
           </div>
        </div>

        {/* Post Header */}
        <header className="mb-10 border-b border-cyber-border/30 pb-8">
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-cyber font-bold text-cyber-text mb-6 leading-tight glow-text break-words">
            {post.title}
          </h1>
          
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
            <div className="flex flex-wrap items-center gap-4 text-cyber-muted font-mono text-xs sm:text-sm">
              <div className="flex items-center gap-2">
                <Calendar className="h-4 w-4 text-cyber-primary" />
                <time>
                  {parseDateLocal(post.date).toLocaleDateString('es-ES', {
                    year: 'numeric',
                    month: 'long',
                    day: 'numeric'
                  })}
                </time>
              </div>
              <span className="text-cyber-border hidden sm:inline">|</span>
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-cyber-primary" />
                <span>{post.readTime || '8 min'} read</span>
              </div>
            </div>
            
            <div className="flex flex-wrap gap-2">
              {post.tags.map((tag: string) => (
                <span
                  key={tag}
                  className="chip-3d chip-3d-sm cursor-default"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        </header>

        {/* Post Content */}
        <div className="markdown-body readable-list">
          {post.description && (
             <blockquote className="border-l-4 border-cyber-primary bg-cyber-primary/5 p-4 rounded-r-lg not-italic text-cyber-text/90 mb-8">
               {post.description}
             </blockquote>
          )}
          
          {post.content && (
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              rehypePlugins={[[rehypeSanitize, {
                ...defaultSchema,
                tagNames: [
                  ...(defaultSchema.tagNames || []),
                  'h1','h2','h3','h4','h5','h6','p','pre','code','span','blockquote','ul','ol','li','table','thead','tbody','tr','th','td','hr', 'img'
                ],
                attributes: {
                  ...defaultSchema.attributes,
                  code: [...(defaultSchema.attributes?.code || []), 'className'],
                  span: [...(defaultSchema.attributes?.span || []), 'className', 'style'],
                  img: [...(defaultSchema.attributes?.img || []), 'className', 'alt', 'src', 'width', 'height'],
                }
              }]]}
              components={{
                code({inline, className, children, ...props}: { inline?: boolean; className?: string; children?: React.ReactNode; [key: string]: unknown }) {
                  const match = /language-(\w+)/.exec(className || '');
                  return !inline && match ? (
                    <div className="relative group my-6 rounded-lg overflow-hidden border border-cyber-border/50 shadow-2xl">
                      <div className="absolute top-0 left-0 right-0 bg-[#1e1e1e] border-b border-white/10 px-4 py-2 flex items-center justify-between">
                         <div className="flex gap-1.5">
                           <div className="w-3 h-3 rounded-full bg-red-500/50"></div>
                           <div className="w-3 h-3 rounded-full bg-yellow-500/50"></div>
                           <div className="w-3 h-3 rounded-full bg-green-500/50"></div>
                         </div>
                         <span className="text-xs font-mono text-white/50">{match[1]}</span>
                      </div>
                      <SyntaxHighlighter
                        style={vscDarkPlus}
                        language={match[1]}
                        PreTag="div"
                        customStyle={{
                          margin: 0,
                          padding: '3rem 1.5rem 1.5rem',
                          background: '#0a0a0a',
                          fontSize: '0.9rem',
                        }}
                        {...props}
                      >
                        {String(children).replace(/\n$/, '')}
                      </SyntaxHighlighter>
                    </div>
                  ) : (
                    <code className="bg-cyber-primary/10 text-cyber-primary px-1.5 py-0.5 rounded font-mono text-sm border border-cyber-primary/20" {...props}>
                      {children}
                    </code>
                  );
                },
                img: ({src, alt}) => (
                   <div className="my-8 relative group">
                      <div className="absolute -inset-1 bg-gradient-to-r from-cyber-primary to-cyber-secondary rounded-lg blur opacity-25 group-hover:opacity-50 transition duration-1000 group-hover:duration-200"></div>
                      <img 
                        src={src} 
                        alt={alt} 
                        className="relative rounded-lg shadow-2xl border border-cyber-border w-full object-cover" 
                        loading="lazy"
                        onError={(e) => {
                          e.currentTarget.style.display = 'none';
                        }}
                      />
                      {alt && <p className="text-center text-sm text-cyber-muted mt-2 font-mono italic">{alt}</p>}
                   </div>
                )
              }}
            >
              {post.content}
            </ReactMarkdown>
          )}
        </div>
        
        {/* Footer Decoration */}
        <div className="mt-12 pt-6 border-t border-cyber-border/30 flex justify-start items-center">
           <button
             onClick={() => navigate(-1)}
             className="inline-flex items-center gap-2 text-cyber-muted hover:text-cyber-primary transition-colors font-mono text-sm"
           >
             <ArrowLeft className="h-4 w-4" />
             Volver
           </button>
        </div>
      </div>
    </motion.article>
  );
}
