package adblock

import "log"

// PredefinedAdBlockLists содержит список популярных списков блокировки
var PredefinedAdBlockLists = map[string]string{
	"easylist":           "https://easylist.to/easylist/easylist.txt",
	"easyprivacy":        "https://easylist.to/easylist/easyprivacy.txt",
	"easyprivacy_ru":     "https://easylist.to/easylist/easyprivacy_ru.txt",
	"ruadlist":           "https://easylist.ru/easylist/ruadlist.txt",
	"ruadlist_plus":      "https://easylist.ru/easylist/ruadlist_plus.txt",
	"adguard_base":       "https://filters.adtidy.org/android/filters/2.txt",
	"adguard_mobile":     "https://filters.adtidy.org/android/filters/11.txt",
	"adguard_russian":    "https://filters.adtidy.org/android/filters/1_optimized.txt",
	"adguard_tracking":   "https://filters.adtidy.org/android/filters/3.txt",
	"adguard_social":     "https://filters.adtidy.org/android/filters/14.txt",
	"peter_lowe":         "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=0&mimetype=plaintext",
}

// LoadDefaultLists загружает стандартные списки блокировки
func (e *Engine) LoadDefaultLists() error {
	lists := []string{
		"easylist",
		"easyprivacy",
	}

	for _, listName := range lists {
		if url, ok := PredefinedAdBlockLists[listName]; ok {
			log.Printf("[AdBlock] Loading list: %s from %s", listName, url)
			if err := e.LoadRulesFromURL(url); err != nil {
				log.Printf("[AdBlock] Failed to load %s: %v", listName, err)
				continue
			}
		}
	}

	return nil
}

