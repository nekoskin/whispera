package utils

import (
	"fmt"
	"testing"
	"time"
	"whispera/internal/obfuscation/core/types"
)

func TestNewRuleEngine(t *testing.T) {
	re := NewRuleEngine()

	if re == nil {
		t.Fatal("NewRuleEngine() returned nil")
	}

	if re.rules == nil {
		t.Error("rules slice is nil")
	}

	if len(re.rules) != 0 {
		t.Error("rules should be empty initially")
	}
}

func TestAddRule(t *testing.T) {
	re := NewRuleEngine()

	rule := types.ObfuscationRule{
		Name: "test_rule",
		Condition: types.Condition{
			Type:     "always",
			Field:    "",
			Operator: "",
			Value:    nil,
		},
		Action: types.Action{
			Type:   "add_padding",
			Method: "add_padding",
			Parameters: map[string]interface{}{
				"size": 64,
			},
			Priority: 1,
			Enabled:  true,
		},
		Parameters: map[string]interface{}{
			"size": 64,
		},
		Priority: 1,
		Enabled:  true,
	}

	_ = re.AddRule(&rule)

	if len(re.rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(re.rules))
	}

	if re.rules[0].Name != "test_rule" {
		t.Errorf("Expected rule name = test_rule, got %s", re.rules[0].Name)
	}
}

func TestRemoveRule(t *testing.T) {
	re := NewRuleEngine()

	rule := types.ObfuscationRule{
		Name: "test_rule",
	}

	_ = re.AddRule(&rule)

	// Удаляем существующее правило
	err := re.RemoveRule("test_rule")
	if err != nil {
		t.Errorf("RemoveRule() error = %v", err)
	}

	if len(re.rules) != 0 {
		t.Errorf("Expected 0 rules after removal, got %d", len(re.rules))
	}

	// Тестируем удаление несуществующего правила
	err = re.RemoveRule("nonexistent")
	if err == nil {
		t.Error("RemoveRule() should return error for nonexistent rule")
	}
}

func TestGetRule(t *testing.T) {
	re := NewRuleEngine()

	rule := types.ObfuscationRule{
		Name: "test_rule",
	}

	_ = re.AddRule(&rule)

	// Получаем существующее правило
	retrievedRule, exists := re.GetRule("test_rule")
	if !exists {
		t.Error("Rule should exist")
	}

	if retrievedRule.Name != "test_rule" {
		t.Errorf("Expected rule name = test_rule, got %s", retrievedRule.Name)
	}

	// Тестируем получение несуществующего правила
	_, exists = re.GetRule("nonexistent")
	if exists {
		t.Error("Nonexistent rule should not exist")
	}
}

func TestListRules(t *testing.T) {
	re := NewRuleEngine()

	// Изначально список должен быть пустым
	rules := re.ListRules()
	if len(rules) != 0 {
		t.Errorf("Expected empty rule list, got %d rules", len(rules))
	}

	// Добавляем несколько правил
	_ = re.AddRule(&types.ObfuscationRule{Name: "rule1", Priority: 1})
	_ = re.AddRule(&types.ObfuscationRule{Name: "rule2", Priority: 2})
	_ = re.AddRule(&types.ObfuscationRule{Name: "rule3", Priority: 3})

	rules = re.ListRules()
	if len(rules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(rules))
	}

	// Проверяем, что правила отсортированы по приоритету (убывание)
	expectedOrder := []string{"rule3", "rule2", "rule1"}
	for i, expected := range expectedOrder {
		if rules[i].Name != expected {
			t.Errorf("Expected rule %d = %s, got %s", i, expected, rules[i].Name)
		}
	}
}

func TestGetEnabledRules(t *testing.T) {
	re := NewRuleEngine()

	// Добавляем правила с разными статусами
	_ = re.AddRule(&types.ObfuscationRule{Name: "enabled1", Enabled: true})
	_ = re.AddRule(&types.ObfuscationRule{Name: "disabled1", Enabled: false})
	_ = re.AddRule(&types.ObfuscationRule{Name: "enabled2", Enabled: true})

	enabledRules := re.GetEnabledRules()
	if len(enabledRules) != 2 {
		t.Errorf("Expected 2 enabled rules, got %d", len(enabledRules))
	}

	// Проверяем, что все возвращенные правила включены
	for _, rule := range enabledRules {
		if !rule.Enabled {
			t.Errorf("Rule %s should be enabled", rule.Name)
		}
	}
}

func TestEnableRule(t *testing.T) {
	re := NewRuleEngine()

	rule := types.ObfuscationRule{
		Name:    "test_rule",
		Enabled: false,
	}

	_ = re.AddRule(&rule)

	// Включаем правило
	err := re.EnableRule("test_rule")
	if err != nil {
		t.Errorf("EnableRule() error = %v", err)
	}

	// Проверяем, что правило включено
	retrievedRule, exists := re.GetRule("test_rule")
	if !exists {
		t.Error("Rule should exist")
	}

	if !retrievedRule.Enabled {
		t.Error("Rule should be enabled")
	}

	// Тестируем включение несуществующего правила
	err = re.EnableRule("nonexistent")
	if err == nil {
		t.Error("EnableRule() should return error for nonexistent rule")
	}
}

func TestDisableRule(t *testing.T) {
	re := NewRuleEngine()

	rule := types.ObfuscationRule{
		Name:    "test_rule",
		Enabled: true,
	}

	_ = re.AddRule(&rule)

	// Отключаем правило
	err := re.DisableRule("test_rule")
	if err != nil {
		t.Errorf("DisableRule() error = %v", err)
	}

	// Проверяем, что правило отключено
	retrievedRule, exists := re.GetRule("test_rule")
	if !exists {
		t.Error("Rule should exist")
	}

	if retrievedRule.Enabled {
		t.Error("Rule should be disabled")
	}

	// Тестируем отключение несуществующего правила
	err = re.DisableRule("nonexistent")
	if err == nil {
		t.Error("DisableRule() should return error for nonexistent rule")
	}
}

func TestUpdateRule(t *testing.T) {
	re := NewRuleEngine()

	originalRule := types.ObfuscationRule{
		Name: "test_rule",
		Action: types.Action{
			Type:    "original_action",
			Method:  "original_action",
			Enabled: true,
		},
		Enabled: true,
	}

	_ = re.AddRule(&originalRule)

	// Обновляем правило
	updatedRule := types.ObfuscationRule{
		Name: "test_rule",
		Action: types.Action{
			Type:    "updated_action",
			Method:  "updated_action",
			Enabled: false,
		},
		Enabled: false,
	}

	err := re.UpdateRule("test_rule", &updatedRule)
	if err != nil {
		t.Errorf("UpdateRule() error = %v", err)
	}

	// Проверяем, что правило обновлено
	retrievedRule, exists := re.GetRule("test_rule")
	if !exists {
		t.Error("Rule should exist after update")
	}

	if retrievedRule.Action.Type != "updated_action" {
		t.Errorf("Expected action = updated_action, got %s", retrievedRule.Action.Type)
	}

	if retrievedRule.Enabled {
		t.Error("Rule should be disabled after update")
	}

	// Тестируем обновление несуществующего правила
	err = re.UpdateRule("nonexistent", &updatedRule)
	if err == nil {
		t.Error("UpdateRule() should return error for nonexistent rule")
	}
}

func TestApplyRules(t *testing.T) {
	re := NewRuleEngine()

	// Добавляем правило для добавления отступов
	rule := types.ObfuscationRule{
		Name: "add_padding_rule",
		Condition: types.Condition{
			Type:     "always",
			Field:    "",
			Operator: "",
			Value:    nil,
		},
		Action: types.Action{
			Type:   "add_padding",
			Method: "add_padding",
			Parameters: map[string]interface{}{
				"size": 64,
			},
			Priority: 1,
			Enabled:  true,
		},
		Parameters: map[string]interface{}{
			"size": 64,
		},
		Enabled: true,
	}

	_ = re.AddRule(&rule)

	// Создаем контекст трафика
	context := &types.TrafficContext{
		Direction: "outbound",
		Protocol:  "udp",
		Size:      100,
		Timestamp: time.Now(),
	}

	// Применяем правила
	testData := []byte("test data")
	processedData, err := re.ApplyRules(testData, context)

	if err != nil {
		t.Errorf("ApplyRules() error = %v", err)
	}

	// Проверяем, что данные обработаны (должны быть добавлены отступы)
	if len(processedData) <= len(testData) {
		t.Error("Processed data should be larger than original data")
	}
}

func TestEvaluateCondition(t *testing.T) {
	re := NewRuleEngine()

	context := &types.TrafficContext{
		Direction:   "outbound",
		Protocol:    "udp",
		Size:        1500,
		ThreatLevel: 8,
	}

	// Тестируем различные условия
	testCases := []struct {
		condition types.Condition
		expected  bool
	}{
		{types.Condition{Type: "always"}, true},
		{types.Condition{Type: "large_packet"}, true},
		{types.Condition{Type: "small_packet"}, false},
		{types.Condition{Type: "outbound"}, true},
		{types.Condition{Type: "inbound"}, false},
		{types.Condition{Type: "high_threat"}, true},
		{types.Condition{Type: "unknown_condition"}, false},
	}

	for _, tc := range testCases {
		condition := tc.condition
		result := re.evaluateCondition(&condition, context)
		if result != tc.expected {
			t.Errorf("Condition '%s': expected %v, got %v", tc.condition.Type, tc.expected, result)
		}
	}
}

func TestApplyAction(t *testing.T) {
	re := NewRuleEngine()

	context := &types.TrafficContext{
		Direction: "outbound",
		Protocol:  "udp",
		Size:      100,
	}

	testData := []byte("test data")

	// Тестируем действие добавления отступов
	params := map[string]interface{}{
		"size": 64,
	}

	processedData, err := re.applyAction("add_padding", testData, params, context)
	if err != nil {
		t.Errorf("applyAction(add_padding) error = %v", err)
	}

	if len(processedData) <= len(testData) {
		t.Error("Processed data should be larger after adding padding")
	}

	// Тестируем неизвестное действие
	processedData, err = re.applyAction("unknown_action", testData, params, context)
	if err != nil {
		t.Errorf("applyAction(unknown_action) error = %v", err)
	}

	if len(processedData) != len(testData) {
		t.Error("Unknown action should not modify data")
	}
}

func TestConcurrentRuleAccess(t *testing.T) {
	re := NewRuleEngine()

	// Тестируем конкурентный доступ к правилам
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			rule := types.ObfuscationRule{
				Name: fmt.Sprintf("rule_%d", id),
				Condition: types.Condition{
					Type:     "always",
					Field:    "",
					Operator: "",
					Value:    nil,
				},
				Action: types.Action{
					Type:       "add_padding",
					Method:     "add_padding",
					Parameters: map[string]interface{}{},
					Priority:   id,
					Enabled:    true,
				},
				Priority: id,
				Enabled:  true,
			}

			_ = re.AddRule(&rule)
			_ = re.EnableRule(fmt.Sprintf("rule_%d", id))
		}(i)
	}

	// Ждем завершения всех горутин
	for i := 0; i < 10; i++ {
		<-done
	}

	// Проверяем, что все правила добавлены
	rules := re.ListRules()
	if len(rules) != 10 {
		t.Errorf("Expected 10 rules, got %d", len(rules))
	}

	// Проверяем, что все правила включены
	enabledRules := re.GetEnabledRules()
	if len(enabledRules) != 10 {
		t.Errorf("Expected 10 enabled rules, got %d", len(enabledRules))
	}
}
