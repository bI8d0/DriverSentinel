//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"runtime"

	"DriverSentinel/repository"
)

func main() {

	if runtime.GOOS != "windows" {
		log.Fatalf("DriverSentinel only supports Windows (current OS: %s)", runtime.GOOS)
	}

	repo, err := repository.NewDriverRepository()
	if err != nil {
		log.Fatalf("Failed to initialize repository: %v", err)
	}

	fmt.Printf("Total drivers loaded: %d\n", len(repo.Drivers))

	driver := repo.Drivers[0]
	fmt.Println(driver.ID)
	fmt.Println(driver.Category)

	// Access a new or future field from the JSON → stored in Extra
	if raw, ok := driver.Extra["NewField"]; ok {
		var val any
		_ = json.Unmarshal(raw, &val)
		fmt.Println(val)
	}
}
