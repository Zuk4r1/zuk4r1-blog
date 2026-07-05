import { useState, useCallback } from 'react';

export interface ReadingAchievement {
  id: string;
  name: string;
  description: string;
  icon: string;
  unlockedAt?: number;
}

export interface UserProgress {
  postsRead: number;
  totalReadTime: number; // en minutos
  tags: Record<string, number>;
  achievements: ReadingAchievement[];
}

const STORAGE_KEY = 'cyber-blog-progress';

const ACHIEVEMENTS: ReadingAchievement[] = [
  {
    id: 'first-post',
    name: 'Primer Vistazo',
    description: 'Lee tu primer post',
    icon: '🔓',
  },
  {
    id: 'pentester-01',
    name: 'Explorador de Vulnerabilidades',
    description: 'Lee 3 posts sobre pentesting',
    icon: '🔍',
  },
  {
    id: 'htb-expert',
    name: 'Experto en HackTheBox',
    description: 'Lee 5 posts sobre HTB',
    icon: '📦',
  },
  {
    id: 'security-master',
    name: 'Maestro de Seguridad',
    description: 'Lee 10 posts totales',
    icon: '⚔️',
  },
  {
    id: 'speed-reader',
    name: 'Lector Rápido',
    description: 'Lee 3 posts en una sesión',
    icon: '⚡',
  },
  {
    id: 'night-hacker',
    name: 'Hacker Nocturno',
    description: 'Lee entre las 10 PM y las 6 AM',
    icon: '🌙',
  },
];

export function useReadingProgress() {
  const [progress, setProgress] = useState<UserProgress>(() => {
    const stored = localStorage.getItem(STORAGE_KEY);
    return stored
      ? JSON.parse(stored)
      : {
          postsRead: 0,
          totalReadTime: 0,
          tags: {},
          achievements: [],
        };
  });

  const checkAchievements = useCallback((currentProgress: UserProgress): ReadingAchievement[] => {
    const unlocked: Record<string, ReadingAchievement> = {};

    // Cargar logros ya desbloqueados
    progress.achievements.forEach((ach) => {
      unlocked[ach.id] = ach;
    });

    // Verificar "Primer Vistazo"
    if (currentProgress.postsRead >= 1 && !unlocked['first-post']) {
      unlocked['first-post'] = { ...ACHIEVEMENTS[0], unlockedAt: Date.now() };
    }

    // Verificar "Explorador de Vulnerabilidades"
    if ((currentProgress.tags['pentesting'] || 0) >= 3 && !unlocked['pentester-01']) {
      unlocked['pentester-01'] = { ...ACHIEVEMENTS[1], unlockedAt: Date.now() };
    }

    // Verificar "Experto en HackTheBox"
    if ((currentProgress.tags['hackthebox'] || 0) >= 5 && !unlocked['htb-expert']) {
      unlocked['htb-expert'] = { ...ACHIEVEMENTS[2], unlockedAt: Date.now() };
    }

    // Verificar "Maestro de Seguridad"
    if (currentProgress.postsRead >= 10 && !unlocked['security-master']) {
      unlocked['security-master'] = { ...ACHIEVEMENTS[3], unlockedAt: Date.now() };
    }

    // Verificar "Hacker Nocturno"
    const hour = new Date().getHours();
    if ((hour >= 22 || hour < 6) && !unlocked['night-hacker']) {
      unlocked['night-hacker'] = { ...ACHIEVEMENTS[5], unlockedAt: Date.now() };
    }

    return Object.values(unlocked);
  }, [progress.achievements]);

  const recordPostRead = useCallback((tags: string[], readTimeMinutes: number) => {
    setProgress((prev) => {
      const newProgress: UserProgress = {
        ...prev,
        postsRead: prev.postsRead + 1,
        totalReadTime: prev.totalReadTime + readTimeMinutes,
        tags: { ...prev.tags },
        achievements: [...prev.achievements],
      };

      // Actualizar conteo de tags
      tags.forEach((tag) => {
        newProgress.tags[tag] = (newProgress.tags[tag] || 0) + 1;
      });

      // Verificar y desbloquear logros
      const newAchievements = checkAchievements(newProgress);
      newProgress.achievements = newAchievements;

      // Guardar en localStorage
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newProgress));
      return newProgress;
    });
  }, [checkAchievements]);

  const getUnlockedAchievements = () => {
    return progress.achievements;
  };

  const resetProgress = () => {
    const resetData: UserProgress = {
      postsRead: 0,
      totalReadTime: 0,
      tags: {},
      achievements: [],
    };
    setProgress(resetData);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(resetData));
  };

  return {
    progress,
    recordPostRead,
    getUnlockedAchievements,
    resetProgress,
  };
}
