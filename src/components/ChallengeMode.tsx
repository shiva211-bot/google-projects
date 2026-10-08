import React, { useState } from 'react';
import { 
  Trophy, 
  Flame, 
  CheckCircle2, 
  XCircle, 
  ArrowRight, 
  RotateCcw, 
  Lightbulb, 
  Award,
  Sparkles 
} from 'lucide-react';
import { SENTINEL_CHALLENGES } from '../constants/challenges';
import { ChallengeItem } from '../types';

export const ChallengeMode: React.FC = () => {
  const [currentIndex, setCurrentIndex] = useState(0);
  const [selectedOptionId, setSelectedOptionId] = useState<string | null>(null);
  const [hasAnswered, setHasAnswered] = useState(false);
  const [score, setScore] = useState(0);
  const [streak, setStreak] = useState(0);
  const [completed, setCompleted] = useState(false);

  const currentChallenge: ChallengeItem = SENTINEL_CHALLENGES[currentIndex];

  const handleSelectOption = (optionId: string) => {
    if (hasAnswered) return;

    setSelectedOptionId(optionId);
    setHasAnswered(true);

    const isCorrect = currentChallenge.options.find((o) => o.id === optionId)?.isCorrect;
    if (isCorrect) {
      const bonus = streak >= 2 ? 50 : 0;
      setScore((prev) => prev + 100 + bonus);
      setStreak((prev) => prev + 1);
    } else {
      setStreak(0);
    }
  };

  const handleNext = () => {
    if (currentIndex < SENTINEL_CHALLENGES.length - 1) {
      setCurrentIndex((prev) => prev + 1);
      setSelectedOptionId(null);
      setHasAnswered(false);
    } else {
      setCompleted(true);
    }
  };

  const handleRestart = () => {
    setCurrentIndex(0);
    setSelectedOptionId(null);
    setHasAnswered(false);
    setScore(0);
    setStreak(0);
    setCompleted(false);
  };

  // Rank determination
  const getRank = (currentScore: number) => {
    if (currentScore >= 500) return { title: 'Zero-Latency Kernel God', color: 'text-amber-400', icon: '👑' };
    if (currentScore >= 400) return { title: 'Staff Systems Architect', color: 'text-emerald-400', icon: '⚡' };
    if (currentScore >= 300) return { title: 'Security Sentinel', color: 'text-cyan-400', icon: '🛡️' };
    if (currentScore >= 150) return { title: 'Performance Craftsman', color: 'text-indigo-400', icon: '⚙️' };
    return { title: 'Junior Padawan', color: 'text-slate-400', icon: '🌱' };
  };

  const rank = getRank(score);

  return (
    <div className="space-y-4">
      {/* Top Gamification Bar */}
      <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-amber-950/80 border border-amber-500/40 flex items-center justify-center text-amber-400 shadow-sm">
            <Trophy className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-slate-100 text-sm">
                Code Sentinel Challenge
              </h3>
              <span className="text-xs text-slate-600">·</span>
              <span className={`text-xs font-medium font-mono ${rank.color}`}>
                {rank.icon} {rank.title}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Spot the security vulnerability or performance bottleneck under real-world conditions.
            </p>
          </div>
        </div>

        {/* Stats */}
        <div className="flex items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-1.5 bg-slate-950 px-3 py-1.5 rounded-md border border-slate-800">
            <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-slate-400">Score:</span>
            <span className="font-bold text-amber-300">{score} XP</span>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-950 px-3 py-1.5 rounded-md border border-slate-800">
            <Flame className={`w-3.5 h-3.5 ${streak > 0 ? 'text-orange-400' : 'text-slate-600'}`} />
            <span className="text-slate-400">Streak:</span>
            <span className={`font-bold ${streak > 1 ? 'text-orange-400 animate-pulse' : 'text-slate-200'}`}>
              {streak}x
            </span>
          </div>

          <div className="text-slate-500 text-[11px]">
            {currentIndex + 1} / {SENTINEL_CHALLENGES.length}
          </div>
        </div>
      </div>

      {completed ? (
        /* Final Results Card */
        <div className="p-8 rounded-lg bg-slate-900/60 border border-slate-800 text-center space-y-4">
          <div className="w-16 h-16 mx-auto rounded-full bg-amber-950/60 border border-amber-500/40 flex items-center justify-center text-amber-400 text-2xl">
            🏆
          </div>
          <div>
            <h4 className="text-base font-bold text-slate-100 font-mono">
              Challenge Completed!
            </h4>
            <p className="text-xs text-slate-400 mt-1">
              You scored <span className="font-bold text-amber-300 font-mono">{score} XP</span> with a final rank of{' '}
              <strong className={rank.color}>{rank.title}</strong>!
            </p>
          </div>

          <div className="pt-2">
            <button
              onClick={handleRestart}
              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white text-xs font-medium rounded-md shadow-sm transition-all inline-flex items-center gap-1.5 font-mono cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>Play Again</span>
            </button>
          </div>
        </div>
      ) : (
        /* Active Challenge */
        <div className="space-y-4">
          {/* Question Card */}
          <div className="p-4 rounded-lg bg-slate-900/50 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between text-xs text-slate-400">
              <span className="font-medium text-slate-200">
                Challenge #{currentIndex + 1}: {currentChallenge.title}
              </span>
              <div className="flex items-center gap-2">
                <span className="text-slate-500 uppercase text-[10px] tracking-wider">
                  {currentChallenge.language}
                </span>
                <span className="text-slate-700">·</span>
                <span className="text-amber-400 text-[11px] font-mono">
                  {currentChallenge.difficulty}
                </span>
              </div>
            </div>

            {/* Code Snippet */}
            <div className="bg-slate-950 border border-slate-800/80 rounded-md p-3 font-mono text-xs text-slate-300 overflow-x-auto leading-relaxed">
              <pre>{currentChallenge.code}</pre>
            </div>

            {/* Question Text */}
            <h4 className="text-xs font-semibold text-slate-100 pt-1">
              {currentChallenge.question}
            </h4>

            {/* Options */}
            <div className="space-y-2 pt-1">
              {currentChallenge.options.map((option) => {
                const isSelected = selectedOptionId === option.id;
                let optionStyle = 'bg-slate-900/80 border-slate-800 hover:border-slate-700 text-slate-300';

                if (hasAnswered) {
                  if (option.isCorrect) {
                    optionStyle = 'bg-emerald-950/40 border-emerald-500/60 text-emerald-200';
                  } else if (isSelected && !option.isCorrect) {
                    optionStyle = 'bg-rose-950/40 border-rose-500/60 text-rose-200';
                  } else {
                    optionStyle = 'bg-slate-950/50 border-slate-800/50 text-slate-600 opacity-60';
                  }
                }

                return (
                  <button
                    key={option.id}
                    onClick={() => handleSelectOption(option.id)}
                    disabled={hasAnswered}
                    className={`w-full text-left p-3 rounded-md border text-xs transition-all flex items-start gap-3 cursor-pointer ${optionStyle}`}
                  >
                    <span className="font-mono text-[11px] w-5 h-5 rounded bg-slate-800 flex items-center justify-center shrink-0 text-slate-300">
                      {option.id.toUpperCase()}
                    </span>
                    <span className="flex-1 leading-relaxed">{option.text}</span>
                    {hasAnswered && option.isCorrect && (
                      <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    )}
                    {hasAnswered && isSelected && !option.isCorrect && (
                      <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Explanation & Next Step */}
          {hasAnswered && (
            <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 space-y-3">
              <div className="flex items-start gap-2.5">
                <Lightbulb className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                <div className="space-y-1.5">
                  <h5 className="text-xs font-semibold text-slate-200">
                    Architectural Deep Dive
                  </h5>
                  <p className="text-xs text-slate-300 leading-relaxed">
                    {currentChallenge.explanation}
                  </p>
                  <p className="text-[11px] font-mono text-emerald-400 pt-1">
                    💡 {currentChallenge.performanceOrSecurityTip}
                  </p>
                </div>
              </div>

              <div className="pt-2 flex justify-end">
                <button
                  onClick={handleNext}
                  className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white text-xs font-medium rounded-md shadow-sm transition-all flex items-center gap-1.5 font-mono cursor-pointer"
                >
                  <span>
                    {currentIndex < SENTINEL_CHALLENGES.length - 1 ? 'Next Challenge' : 'View Results'}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
