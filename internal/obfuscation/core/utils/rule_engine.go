package utils

import (
	"fmt"
	"sync"
	"whispera/internal/obfuscation/core/types"
)

// RuleEngineImpl - реализация движка правил
type RuleEngineImpl struct {
	rules []*types.ObfuscationRule
	mutex sync.RWMutex
}

// NewRuleEngine создает новый движок правил
func NewRuleEngine() *RuleEngineImpl {
	return &RuleEngineImpl{
		rules: make([]*types.ObfuscationRule, 0),
	}
}

// GetRules возвращает все правила
func (re *RuleEngineImpl) GetRules() []*types.ObfuscationRule {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	rules := make([]*types.ObfuscationRule, len(re.rules))
	copy(rules, re.rules)
	return rules
}

// AddRule добавляет новое правило
func (re *RuleEngineImpl) AddRule(rule *types.ObfuscationRule) error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	re.rules = append(re.rules, rule)
	return nil
}

// RemoveRule удаляет правило по имени
func (re *RuleEngineImpl) RemoveRule(name string) error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	for i, rule := range re.rules {
		if rule.Name == name {
			re.rules = append(re.rules[:i], re.rules[i+1:]...)
			return nil
		}
	}

	return fmt.Errorf("rule %s not found", name)
}

// EvaluateRules оценивает правила для контекста
func (re *RuleEngineImpl) EvaluateRules(context *types.TrafficContext) []*types.ObfuscationRule {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	var applicableRules []*types.ObfuscationRule

	for _, rule := range re.rules {
		if rule.Enabled && re.evaluateCondition(&rule.Condition, context) {
			applicableRules = append(applicableRules, rule)
		}
	}

	return applicableRules
}

// evaluateCondition оценивает условие правила
func (re *RuleEngineImpl) evaluateCondition(condition *types.Condition, context *types.TrafficContext) bool {
	// Простая реализация оценки условий
	// В реальной реализации нужно парсить и выполнять условия
	switch condition.Type {
	case "always":
		return true
	case "high_threat":
		return context.ThreatLevel > 7
	case "outbound":
		return context.Direction == "outbound"
	case "large_packet":
		return context.Size > 1000
	case "small_packet":
		return context.Size < 100
	case "inbound":
		return context.Direction == "inbound"
	default:
		return false
	}
}

// ApplyRules применяет правила к данным
func (re *RuleEngineImpl) ApplyRules(data []byte, context *types.TrafficContext) ([]byte, error) {
	rules := re.EvaluateRules(context)

	processedData := data
	for _, rule := range rules {
		// Применяем действие правила
		var err error
		processedData, err = re.applyAction(rule.Action.Type, processedData, rule.Action.Parameters, context)
		if err != nil {
			return data, err
		}
	}

	return processedData, nil
}

// GetRule возвращает правило по имени
func (re *RuleEngineImpl) GetRule(name string) (*types.ObfuscationRule, bool) {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	for _, rule := range re.rules {
		if rule.Name == name {
			return rule, true
		}
	}
	return nil, false
}

// ListRules возвращает список всех правил, отсортированный по приоритету (убывание)
func (re *RuleEngineImpl) ListRules() []*types.ObfuscationRule {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	rules := make([]*types.ObfuscationRule, len(re.rules))
	copy(rules, re.rules)

	// Сортируем по приоритету (убывание)
	for i := 0; i < len(rules)-1; i++ {
		for j := i + 1; j < len(rules); j++ {
			if rules[i].Priority < rules[j].Priority {
				rules[i], rules[j] = rules[j], rules[i]
			}
		}
	}

	return rules
}

// GetEnabledRules возвращает список включенных правил
func (re *RuleEngineImpl) GetEnabledRules() []*types.ObfuscationRule {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	var enabledRules []*types.ObfuscationRule
	for _, rule := range re.rules {
		if rule.Enabled {
			enabledRules = append(enabledRules, rule)
		}
	}
	return enabledRules
}

// EnableRule включает правило
func (re *RuleEngineImpl) EnableRule(name string) error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	for _, rule := range re.rules {
		if rule.Name == name {
			rule.Enabled = true
			return nil
		}
	}
	return fmt.Errorf("rule %s not found", name)
}

// DisableRule отключает правило
func (re *RuleEngineImpl) DisableRule(name string) error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	for _, rule := range re.rules {
		if rule.Name == name {
			rule.Enabled = false
			return nil
		}
	}
	return fmt.Errorf("rule %s not found", name)
}

// UpdateRule обновляет правило
func (re *RuleEngineImpl) UpdateRule(name string, newRule *types.ObfuscationRule) error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	for i, rule := range re.rules {
		if rule.Name == name {
			re.rules[i] = newRule
			return nil
		}
	}
	return fmt.Errorf("rule %s not found", name)
}

// applyAction применяет действие правила
func (re *RuleEngineImpl) applyAction(
	action string, data []byte, params map[string]interface{}, context *types.TrafficContext,
) ([]byte, error) {
	if context != nil && context.Direction != "" {
		// Use metadata for action context
	}

	switch action {
	case "add_padding":
		paddingSize := 64 // default
		if size, ok := params["size"].(int); ok && size > 0 {
			paddingSize = size
		}
		padding := make([]byte, paddingSize)
		for i := range padding {
			padding[i] = byte(i % 256)
		}
		return append(data, padding...), nil
	default:
		// Unknown action - return data unchanged
		return data, nil
	}
}
