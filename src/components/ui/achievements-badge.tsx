import { motion, AnimatePresence } from 'framer-motion';
import { ReadingAchievement } from '@hooks/use-reading-progress';

interface AchievementsBadgeProps {
  achievements: ReadingAchievement[];
  onDismiss?: (id: string) => void;
}

export function AchievementsBadge({ achievements, onDismiss }: AchievementsBadgeProps) {
  // Mostrar solo los 3 últimos logros desbloqueados
  const recentAchievements = achievements.slice(-3);

  return (
    <div className="fixed bottom-4 right-4 z-40">
      <AnimatePresence>
        {recentAchievements.map((achievement, index) => (
          <motion.div
            key={achievement.id}
            initial={{ opacity: 0, x: 100, y: 0 }}
            animate={{ 
              opacity: 1, 
              x: 0, 
              y: index * 80,
              transition: { delay: index * 0.1 }
            }}
            exit={{ opacity: 0, x: 100 }}
            className="mb-4 bg-cyber-card/95 backdrop-blur-md border-2 border-cyber-primary/60 rounded-lg p-4 max-w-xs"
          >
            <div className="flex items-start gap-3">
              <motion.div
                className="text-3xl flex-shrink-0"
                animate={{ scale: [1, 1.2, 1] }}
                transition={{ duration: 0.6, delay: 0.3 }}
              >
                {achievement.icon}
              </motion.div>
              <div>
                <motion.h3 
                  className="text-sm font-cyber font-bold text-cyber-primary"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.4 }}
                >
                  ¡LOGRO DESBLOQUEADO!
                </motion.h3>
                <motion.p
                  className="text-xs text-white/80 mt-1 font-mono"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 }}
                >
                  {achievement.name}
                </motion.p>
                <motion.p
                  className="text-xs text-cyber-muted mt-1"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.6 }}
                >
                  {achievement.description}
                </motion.p>
              </div>
              {onDismiss && (
                <motion.button
                  onClick={() => onDismiss(achievement.id)}
                  className="text-cyber-muted hover:text-cyber-primary transition-colors text-lg"
                  whileHover={{ scale: 1.1 }}
                >
                  ✕
                </motion.button>
              )}
            </div>

            {/* Efecto de brillo */}
            <motion.div
              className="absolute inset-0 bg-gradient-to-r from-cyber-primary/10 via-transparent to-transparent rounded-lg pointer-events-none"
              animate={{
                opacity: [0, 0.5, 0],
              }}
              transition={{ duration: 1, repeat: Infinity }}
            />
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
