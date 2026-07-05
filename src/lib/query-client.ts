import { QueryClient } from '@tanstack/react-query';

/**
 * Instancia única de QueryClient para toda la aplicación
 * Centraliza la configuración de React Query
 */
export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5,      // 5 minutos
      retry: 1,
      refetchOnWindowFocus: false,
      refetchOnMount: false,
    },
    mutations: {
      retry: 1,
    },
  },
});
