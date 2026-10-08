package memory

import (
	"fmt"
	"math"
	"time"
)

// LearningEngine updates strategies, rankings, and empirical experience without touching neural weights.
type LearningEngine struct {
	DB *ExperienceDB
}

func NewLearningEngine(db *ExperienceDB) *LearningEngine {
	return &LearningEngine{DB: db}
}

// LearnFromExecution updates Strategy Memory and Tool Effectiveness based on the Verifier outcome.
func (le *LearningEngine) LearnFromExecution(contextStr, hypothesis, bestAction, toolName string, confirmed bool, reason, actualIssue, targetURL string) {
	le.DB.mu.Lock()
	defer le.DB.mu.Unlock()

	key := fmt.Sprintf("%s|%s", contextStr, hypothesis)

	// 1. Update Strategy Memory
	strategy, exists := le.DB.Strategies[key]
	if !exists {
		strategy = &StrategyMemory{
			Context:     contextStr,
			Hypothesis:  hypothesis,
			BestAction:  bestAction,
			TrialsCount: 0,
			LastUpdated: time.Now(),
		}
		le.DB.Strategies[key] = strategy
	}

	strategy.TrialsCount++
	if confirmed {
		strategy.ConfirmedCount++
	} else {
		strategy.FalsePositiveCount++
	}

	// Recalculate success rate
	if strategy.TrialsCount > 0 {
		rate := (float64(strategy.ConfirmedCount) / float64(strategy.TrialsCount)) * 100.0
		strategy.SuccessRate = math.Round(rate*10) / 10
	}
	strategy.LastUpdated = time.Now()

	// 2. Update Tool Effectiveness Memory
	toolMem, exists := le.DB.ToolEffectiveness[contextStr]
	if !exists {
		toolMem = &ToolEffectivenessMemory{
			Context:        contextStr,
			ToolScores:     make(map[string]float64),
			ExecutionCount: make(map[string]int),
			LastUpdated:    time.Now(),
		}
		le.DB.ToolEffectiveness[contextStr] = toolMem
	}

	toolMem.ExecutionCount[toolName]++
	currentScore, hasScore := toolMem.ToolScores[toolName]
	if !hasScore {
		currentScore = 50.0
	}

	// Dynamic Bayesian-style adjustment step
	delta := 4.0
	if confirmed {
		currentScore += delta
		if currentScore > 99.0 {
			currentScore = 99.0
		}
	} else {
		currentScore -= delta
		if currentScore < 5.0 {
			currentScore = 5.0
		}
	}
	toolMem.ToolScores[toolName] = math.Round(currentScore*10) / 10
	toolMem.LastUpdated = time.Now()

	// 3. Update Failure Memory if rejected
	if !confirmed {
		failRecord := FailureMemory{
			ID:            fmt.Sprintf("fail_%d", time.Now().UnixNano()),
			TargetURL:     targetURL,
			WhatAIThought: hypothesis,
			ActionTaken:   bestAction,
			WhyWasItWrong: reason,
			ActualIssue:   actualIssue,
			LessonLearned: fmt.Sprintf("In context '%s', avoid asserting '%s' without explicit response validation: %s", contextStr, hypothesis, reason),
			RecordedAt:    time.Now(),
		}
		le.DB.Failures = append(le.DB.Failures, failRecord)
	}
}
