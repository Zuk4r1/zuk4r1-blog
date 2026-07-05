import { useEffect, useState, useCallback } from 'react';
import { getAllPosts, getPublishedPosts, subscribeToPosts, Post } from '@/lib/posts';

/**
 * Hook reutilizable para suscribirse a cambios de posts con soporte HMR
 * Consolida la lógica duplicada de subscripción en un único lugar
 */
export function usePostsSubscription(callback: (posts: Post[]) => void) {
  useEffect(() => {
    let unsub: (() => void) | null = null;
    
    const metaWithHot = import.meta as ImportMeta & { hot?: { accept: (cb: (mod: unknown) => void) => void } };
    if (import.meta && metaWithHot.hot) {
      unsub = subscribeToPosts(callback);
    }

    return () => {
      if (unsub) unsub();
    };
  }, [callback]);
}

export function usePublishedPosts() {
  const [posts, setPosts] = useState<Post[]>([]);

  useEffect(() => {
    getPublishedPosts().then(setPosts).catch(console.error);
  }, []);

  const handlePostsUpdate = useCallback((updated: Post[]) => {
    setPosts(updated.filter((p) => p.published));
  }, []);

  usePostsSubscription(handlePostsUpdate);

  return posts;
}

export function useAllPosts() {
  const [posts, setPosts] = useState<Post[]>([]);

  useEffect(() => {
    getAllPosts().then(setPosts).catch(console.error);
  }, []);

  const handlePostsUpdate = useCallback((updated: Post[]) => {
    setPosts(updated);
  }, []);

  usePostsSubscription(handlePostsUpdate);

  return posts;
}
