package evasion

import (
	"fmt"
	"testing"
	"time"
	"whispera/internal/obfuscation/core/types"
)

const testProfileName = "test_profile"

func TestNewProfileManager(t *testing.T) {
	pm := NewProfileManager()

	if pm == nil {
		t.Fatal("NewProfileManager() returned nil")
	}

	if pm.profiles == nil {
		t.Error("profiles map is nil")
	}

	if pm.active != "" {
		t.Error("active profile should be empty initially")
	}
}

func TestAddProfile(t *testing.T) {
	pm := NewProfileManager()

	profile := &types.TrafficProfile{
		Name: testProfileName,
		Type: "test",
		PacketSizes: types.SizeDistribution{
			Min: 100,
			Max: 1000,
		},
		CreatedAt: time.Now(),
	}

	pm.AddProfile(testProfileName, profile)

	// Проверяем, что профиль добавлен
	if len(pm.profiles) != 1 {
		t.Errorf("Expected 1 profile, got %d", len(pm.profiles))
	}

	if pm.profiles[testProfileName] == nil {
		t.Error("Profile not found in profiles map")
	}

	if pm.profiles[testProfileName].Name != testProfileName {
		t.Error("Profile name not set correctly")
	}
}

func TestGetProfile(t *testing.T) {
	pm := NewProfileManager()

	profile := &types.TrafficProfile{
		Name: testProfileName,
		Type: "test",
	}

	pm.AddProfile(testProfileName, profile)

	// Тестируем получение существующего профиля
	retrievedProfile, exists := pm.GetProfile(testProfileName)
	if !exists {
		t.Error("Profile should exist")
	}

	if retrievedProfile.Name != testProfileName {
		t.Errorf("Expected profile name = test_profile, got %s", retrievedProfile.Name)
	}

	// Тестируем получение несуществующего профиля
	_, exists = pm.GetProfile("nonexistent")
	if exists {
		t.Error("Nonexistent profile should not exist")
	}
}

func TestSetActiveProfile(t *testing.T) {
	pm := NewProfileManager()

	profile := &types.TrafficProfile{
		Name: testProfileName,
		Type: "test",
	}

	pm.AddProfile(testProfileName, profile)

	// Тестируем установку существующего профиля
	err := pm.SetActiveProfile(testProfileName)
	if err != nil {
		t.Errorf("SetActiveProfile() error = %v", err)
	}

	if pm.active != testProfileName {
		t.Errorf("Expected active profile = test_profile, got %s", pm.active)
	}

	// Тестируем установку несуществующего профиля
	err = pm.SetActiveProfile("nonexistent")
	if err == nil {
		t.Error("SetActiveProfile() should return error for nonexistent profile")
	}
}

func TestGetActiveProfile(t *testing.T) {
	pm := NewProfileManager()

	// Изначально активный профиль должен быть пустым
	active := pm.GetActiveProfile()
	if active != "" {
		t.Errorf("Expected empty active profile, got %s", active)
	}

	// Устанавливаем активный профиль
	profile := &types.TrafficProfile{Name: testProfileName, Type: "test"}
	pm.AddProfile(testProfileName, profile)
	_ = pm.SetActiveProfile(testProfileName)

	active = pm.GetActiveProfile()
	if active != testProfileName {
		t.Errorf("Expected active profile = test_profile, got %s", active)
	}
}

func TestListProfiles(t *testing.T) {
	pm := NewProfileManager()

	// Изначально список должен быть пустым
	profiles := pm.ListProfiles()
	if len(profiles) != 0 {
		t.Errorf("Expected empty profile list, got %d profiles", len(profiles))
	}

	// Добавляем несколько профилей
	pm.AddProfile("profile1", &types.TrafficProfile{Name: "profile1", Type: "test"})
	pm.AddProfile("profile2", &types.TrafficProfile{Name: "profile2", Type: "test"})
	pm.AddProfile("profile3", &types.TrafficProfile{Name: "profile3", Type: "test"})

	profiles = pm.ListProfiles()
	if len(profiles) != 3 {
		t.Errorf("Expected 3 profiles, got %d", len(profiles))
	}

	// Проверяем, что все профили присутствуют
	profileMap := make(map[string]bool)
	for _, name := range profiles {
		profileMap[name] = true
	}

	expectedProfiles := []string{"profile1", "profile2", "profile3"}
	for _, expected := range expectedProfiles {
		if !profileMap[expected] {
			t.Errorf("Profile %s not found in list", expected)
		}
	}
}

func TestRemoveProfile(t *testing.T) {
	pm := NewProfileManager()

	profile := &types.TrafficProfile{Name: testProfileName, Type: "test"}
	pm.AddProfile(testProfileName, profile)
	_ = pm.SetActiveProfile(testProfileName)

	// Удаляем профиль
	err := pm.RemoveProfile(testProfileName)
	if err != nil {
		t.Errorf("RemoveProfile() error = %v", err)
	}

	// Проверяем, что профиль удален
	_, exists := pm.GetProfile(testProfileName)
	if exists {
		t.Error("Profile should not exist after removal")
	}

	// Проверяем, что активный профиль сброшен
	if pm.active != "" {
		t.Error("Active profile should be reset after removal")
	}

	// Тестируем удаление несуществующего профиля
	err = pm.RemoveProfile("nonexistent")
	if err == nil {
		t.Error("RemoveProfile() should return error for nonexistent profile")
	}
}

func TestUpdateProfile(t *testing.T) {
	pm := NewProfileManager()

	originalProfile := &types.TrafficProfile{
		Name: testProfileName,
		Type: "original",
		PacketSizes: types.SizeDistribution{
			Min: 100,
			Max: 1000,
		},
	}

	pm.AddProfile(testProfileName, originalProfile)

	// Обновляем профиль
	updatedProfile := &types.TrafficProfile{
		Name: testProfileName,
		Type: "updated",
		PacketSizes: types.SizeDistribution{
			Min: 200,
			Max: 2000,
		},
	}

	err := pm.UpdateProfile(testProfileName, updatedProfile)
	if err != nil {
		t.Errorf("UpdateProfile() error = %v", err)
	}

	// Проверяем, что профиль обновлен
	retrievedProfile, exists := pm.GetProfile(testProfileName)
	if !exists {
		t.Error("Profile should exist after update")
	}

	if retrievedProfile.Type != "updated" {
		t.Errorf("Expected profile type = updated, got %s", retrievedProfile.Type)
	}

	if retrievedProfile.PacketSizes.Min != 200 {
		t.Errorf("Expected min packet size = 200, got %d", retrievedProfile.PacketSizes.Min)
	}

	// Тестируем обновление несуществующего профиля
	err = pm.UpdateProfile("nonexistent", updatedProfile)
	if err == nil {
		t.Error("UpdateProfile() should return error for nonexistent profile")
	}
}

func TestGetProfileStats(t *testing.T) {
	pm := NewProfileManager()

	profile := &types.TrafficProfile{
		Name:       testProfileName,
		Type:       "test",
		CreatedAt:  time.Now(),
		LastUsed:   time.Now(),
		UsageCount: 5,
	}

	pm.AddProfile(testProfileName, profile)
	_ = pm.SetActiveProfile(testProfileName)

	stats := pm.GetProfileStats()

	if len(stats) != 1 {
		t.Errorf("Expected 1 profile stat, got %d", len(stats))
	}

	stat, exists := stats[testProfileName]
	if !exists {
		t.Error("Profile stat not found")
	}

	if stat.Name != testProfileName {
		t.Errorf("Expected stat name = test_profile, got %s", stat.Name)
	}

	if stat.Type != "test" {
		t.Errorf("Expected stat type = test, got %s", stat.Type)
	}

	if !stat.IsActive {
		t.Error("Profile should be marked as active")
	}

	if stat.UsageCount != 5 {
		t.Errorf("Expected usage count = 5, got %d", stat.UsageCount)
	}
}

func TestConcurrentProfileAccess(t *testing.T) {
	pm := NewProfileManager()

	// Тестируем конкурентный доступ к профилям
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			profile := &types.TrafficProfile{
				Name: fmt.Sprintf("profile_%d", id),
				Type: "test",
			}

			pm.AddProfile(fmt.Sprintf("profile_%d", id), profile)
			_ = pm.SetActiveProfile(fmt.Sprintf("profile_%d", id))
		}(i)
	}

	// Ждем завершения всех горутин
	for i := 0; i < 10; i++ {
		<-done
	}

	// Проверяем, что все профили добавлены
	profiles := pm.ListProfiles()
	if len(profiles) != 10 {
		t.Errorf("Expected 10 profiles, got %d", len(profiles))
	}
}
