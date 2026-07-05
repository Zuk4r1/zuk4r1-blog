import { useState, useEffect, useMemo, useCallback, useDeferredValue } from 'react';
import { getPublishedPosts, Post } from '@/lib/posts';
import { usePostsSubscription } from './use-posts';

export interface SearchResult {
  post: Post;
  relevance: number;
  matchedFields: string[];
}

export function useSearch(query: string, minQueryLength = 2) {
  const [allPosts, setAllPosts] = useState<Post[]>([]);
  const [isLoadingPosts, setIsLoadingPosts] = useState(true);
  const deferredQuery = useDeferredValue(query);

  // Cargar todos los posts publicados una sola vez
  useEffect(() => {
    let isMounted = true;

    async function loadPosts() {
      try {
        setIsLoadingPosts(true);
        const posts = await getPublishedPosts();
        if (isMounted) {
          setAllPosts(posts);
        }
      } catch (error) {
        console.error('Error al cargar posts para búsqueda:', error);
      } finally {
        if (isMounted) {
          setIsLoadingPosts(false);
        }
      }
    }

    loadPosts();

    return () => {
      isMounted = false;
    };
  }, []);

  // Suscribirse a cambios de posts (HMR)
  const handlePostsUpdate = useCallback((updated: Post[]) => {
    setAllPosts(updated.filter((p) => p.published));
  }, []);

  usePostsSubscription(handlePostsUpdate);

  // Función de búsqueda mejorada (PURA - sin side effects)
  const searchResults = useMemo(() => {
    const normalizedQuery = deferredQuery.trim().toLowerCase();
    if (!normalizedQuery || normalizedQuery.length < minQueryLength) {
      return [];
    }
    
    const searchTerm = normalizedQuery;
    const searchResults: SearchResult[] = [];

    allPosts.forEach((post) => {
      let relevance = 0;
      const matchedFields: string[] = [];

      // Búsqueda en título (mayor relevancia)
      const titleLower = post.title.toLowerCase();
      if (titleLower.includes(searchTerm)) {
        relevance += 10;
        matchedFields.push('título');
        // Bonus si el título empieza con el término
        if (titleLower.startsWith(searchTerm)) {
          relevance += 5;
        }
      }

      // Búsqueda en etiquetas (alta relevancia)
      post.tags.forEach((tag) => {
        const tagLower = tag.toLowerCase();
        if (tagLower.includes(searchTerm)) {
          relevance += 8;
          if (!matchedFields.includes('etiquetas')) {
            matchedFields.push('etiquetas');
          }
          // Bonus si la etiqueta empieza con el término
          if (tagLower.startsWith(searchTerm)) {
            relevance += 3;
          }
        }
      });

      // Búsqueda en descripción (media relevancia)
      const descriptionLower = post.description.toLowerCase();
      if (descriptionLower.includes(searchTerm)) {
        relevance += 6;
        matchedFields.push('descripción');
      }

      // Búsqueda en fecha (formato YYYY-MM-DD)
      if (post.date.includes(searchTerm)) {
        relevance += 4;
        matchedFields.push('fecha');
      }

      // Búsqueda en contenido (baja relevancia)
      if (post.content) {
        const contentLower = post.content.toLowerCase();
        if (contentLower.includes(searchTerm)) {
          relevance += 2;
          matchedFields.push('contenido');
        }
      }

      // Si hay coincidencias, agregar a resultados
      if (relevance > 0) {
        searchResults.push({
          post,
          relevance,
          matchedFields
        });
      }
    });

    // Ordenar por relevancia (descendente)
    searchResults.sort((a, b) => b.relevance - a.relevance);

    return searchResults;
  }, [deferredQuery, allPosts, minQueryLength]);

  const isLoading = (deferredQuery !== query && query.length >= minQueryLength) || (isLoadingPosts && query.length >= minQueryLength);

  return {
    results: searchResults,
    isLoading,
    hasResults: searchResults.length > 0,
    totalResults: searchResults.length
  };
}
