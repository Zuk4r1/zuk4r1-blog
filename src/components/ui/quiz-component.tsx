import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { CheckCircle, XCircle, RotateCcw } from 'lucide-react';
import { glowAnimationVariants } from '@/lib/animations';

export interface QuizQuestion {
  id: string;
  question: string;
  options: string[];
  correctAnswer: number;
  explanation?: string;
}

interface QuizComponentProps {
  questions: QuizQuestion[];
  title?: string;
  onComplete?: (score: number, total: number) => void;
}

export function QuizComponent({ 
  questions, 
  title = 'Prueba tu Conocimiento',
  onComplete 
}: QuizComponentProps) {
  const [currentQuestion, setCurrentQuestion] = useState(0);
  const [score, setScore] = useState(0);
  const [selectedAnswer, setSelectedAnswer] = useState<number | null>(null);
  const [showFeedback, setShowFeedback] = useState(false);
  const [isAnswered, setIsAnswered] = useState(false);
  const [completed, setCompleted] = useState(false);

  const handleSelectAnswer = (answerIndex: number) => {
    if (isAnswered) return;
    
    setSelectedAnswer(answerIndex);
    setShowFeedback(true);
    setIsAnswered(true);

    if (answerIndex === questions[currentQuestion].correctAnswer) {
      setScore(score + 1);
    }
  };

  const handleNext = () => {
    if (currentQuestion + 1 < questions.length) {
      setCurrentQuestion(currentQuestion + 1);
      setSelectedAnswer(null);
      setShowFeedback(false);
      setIsAnswered(false);
    } else {
      setCompleted(true);
      onComplete?.(score + (selectedAnswer === questions[currentQuestion].correctAnswer ? 1 : 0), questions.length);
    }
  };

  const handleReset = () => {
    setCurrentQuestion(0);
    setScore(0);
    setSelectedAnswer(null);
    setShowFeedback(false);
    setIsAnswered(false);
    setCompleted(false);
  };

  if (questions.length === 0) {
    return null;
  }

  const question = questions[currentQuestion];
  const isCorrect = selectedAnswer === question.correctAnswer;

  return (
    <motion.div
      className="my-8 rounded-lg border-2 border-cyber-primary/50 bg-black/60 backdrop-blur-md overflow-hidden"
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
    >
      {/* Header */}
      <motion.div
        className="bg-cyber-primary/10 border-b border-cyber-primary/30 px-6 py-4"
        animate={glowAnimationVariants.container.animate}
        transition={glowAnimationVariants.container.transition}
      >
        <h3 className="text-lg font-cyber text-cyber-primary uppercase tracking-widest">
          {title}
        </h3>
        <div className="mt-2 flex items-center justify-between text-sm font-mono text-cyber-text">
          <span>Pregunta {currentQuestion + 1} de {questions.length}</span>
          <span className="text-cyber-primary">
            Puntuación: {score}/{questions.length}
          </span>
        </div>
      </motion.div>

      {/* Contenido */}
      <div className="p-6">
        {completed ? (
          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            className="text-center py-8"
          >
            <motion.div
              className="text-6xl mb-4"
              animate={{ scale: [1, 1.1, 1] }}
              transition={{ duration: 0.6 }}
            >
              🎯
            </motion.div>
            <h4 className="text-2xl font-cyber text-cyber-primary mb-2">
              ¡Prueba Completada!
            </h4>
            <p className="text-cyber-text mb-6 font-mono">
              Obtuviste <span className="text-cyber-primary text-lg font-bold">{score}/{questions.length}</span> respuestas correctas
            </p>
            <motion.button
              onClick={handleReset}
              className="flex items-center gap-2 bg-cyber-primary text-black px-6 py-2 rounded-lg font-cyber font-bold uppercase hover:shadow-neon-strong transition-all"
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
            >
              <RotateCcw className="h-4 w-4" />
              Reintentar
            </motion.button>
          </motion.div>
        ) : (
          <motion.div
            key={currentQuestion}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
          >
            {/* Pregunta */}
            <motion.h4 
              className="text-lg font-cyber text-white mb-6 leading-relaxed"
              animate={{ textShadow: [
                '0 0 10px rgba(0, 255, 159, 0)',
                '0 0 20px rgba(0, 255, 159, 0.3)',
                '0 0 10px rgba(0, 255, 159, 0)',
              ] }}
              transition={{ duration: 3, repeat: Infinity }}
            >
              {question.question}
            </motion.h4>

            {/* Opciones */}
            <div className="space-y-3 mb-6">
              {question.options.map((option, index) => (
                <motion.button
                  key={index}
                  onClick={() => handleSelectAnswer(index)}
                  disabled={isAnswered}
                  className={`w-full text-left p-4 rounded-lg border-2 transition-all duration-300 font-mono text-sm ${
                    selectedAnswer === index
                      ? isCorrect
                        ? 'border-green-500/60 bg-green-500/10 text-green-400'
                        : 'border-red-500/60 bg-red-500/10 text-red-400'
                      : 'border-cyber-border/50 bg-cyber-card/40 text-cyber-text hover:border-cyber-primary/50 hover:bg-cyber-primary/5'
                  } ${isAnswered ? 'cursor-default' : 'cursor-pointer hover:translate-x-1'}`}
                  whileHover={!isAnswered ? { x: 5 } : {}}
                >
                  <div className="flex items-center gap-3">
                    <div className={`w-6 h-6 rounded-full border-2 flex items-center justify-center ${
                      selectedAnswer === index
                        ? isCorrect
                          ? 'border-green-500 bg-green-500/20'
                          : 'border-red-500 bg-red-500/20'
                        : 'border-cyber-primary/30'
                    }`}>
                      {selectedAnswer === index && (
                        isCorrect ? (
                          <CheckCircle className="h-4 w-4 text-green-400" />
                        ) : (
                          <XCircle className="h-4 w-4 text-red-400" />
                        )
                      )}
                    </div>
                    <span>{option}</span>
                  </div>
                </motion.button>
              ))}
            </div>

            {/* Feedback */}
            <AnimatePresence>
              {showFeedback && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className={`p-4 rounded-lg border mb-6 font-mono text-sm ${
                    isCorrect
                      ? 'border-green-500/50 bg-green-500/10 text-green-400'
                      : 'border-red-500/50 bg-red-500/10 text-red-400'
                  }`}
                >
                  <p className="font-bold mb-1">
                    {isCorrect ? '✓ ¡Correcto!' : '✗ Incorrecto'}
                  </p>
                  {question.explanation && (
                    <p className="text-xs opacity-90">{question.explanation}</p>
                  )}
                </motion.div>
              )}
            </AnimatePresence>

            {/* Botón Siguiente */}
            {isAnswered && (
              <motion.button
                onClick={handleNext}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="w-full bg-cyber-primary text-black px-6 py-3 rounded-lg font-cyber font-bold uppercase hover:shadow-neon-strong transition-all"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                {currentQuestion + 1 === questions.length ? 'Finalizar' : 'Siguiente'}
              </motion.button>
            )}
          </motion.div>
        )}
      </div>

      {/* Barra de progreso */}
      <motion.div className="h-1 bg-cyber-border/30">
        <motion.div
          className="h-full bg-gradient-to-r from-cyber-primary to-cyber-secondary"
          animate={{
            width: `${((currentQuestion + 1) / questions.length) * 100}%`,
          }}
          transition={{ duration: 0.5 }}
        />
      </motion.div>
    </motion.div>
  );
}
