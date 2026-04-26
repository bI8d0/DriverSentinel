package main

import (
	"encoding/json"
	"fmt"
	"log"

	"DriverSentinel_/repository"
)

func main() {
	repo, err := repository.NewDriverRepository()
	if err != nil {
		log.Fatalf("Failed to initialize repository: %v", err)
	}

	fmt.Printf("Total drivers loaded: %d\n", len(repo.Drivers))

	driver := repo.Drivers[0]
	fmt.Println(driver.ID)
	fmt.Println(driver.Category)

	// Campo nuevo/futuro del JSON → en Extra
	if raw, ok := driver.Extra["NuevoCampo"]; ok {
		var val any
		_ = json.Unmarshal(raw, &val)
		fmt.Println(val)
	}
}
