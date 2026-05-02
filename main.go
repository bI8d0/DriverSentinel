//go:build windows

package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"

	"DriverSentinel/repository"
	"DriverSentinel/scan"
)

func main() {

	if runtime.GOOS != "windows" {
		log.Fatalf("DriverSentinel only supports Windows (current OS: %s)", runtime.GOOS)
	}

	// Define command line flags
	scanPath := flag.String("path", "", "Path of directory to scan")
	recursive := flag.Bool("r", false, "Scan recursively")
	scanCommon := flag.Bool("common", false, "Scan common Windows driver locations (Admin only)")
	flag.Parse()

	// Initialize vulnerable drivers repository
	fmt.Println("\n=== DriverSentinel v1.0 - Vulnerable Driver Scanner by bI8d0 ===\n")

	repo, err := repository.NewDriverRepository()
	if err != nil {
		log.Fatalf("Failed to initialize repository: %v", err)
	}

	fmt.Printf("Total drivers loaded: %d\n\n", len(repo.Drivers))

	// Create the scanner
	scanner := scan.NewScanner(repo)

	// Determine what to scan
	if *scanCommon {
		// Scan common driver locations
		if err := scanner.ScanCommonDriverPaths(); err != nil {
			log.Fatalf("Error scanning common locations: %v", err)
		}
	} else if *scanPath != "" {
		// Scan specified path
		if err := scanner.ScanDirectory(*scanPath, *recursive); err != nil {
			log.Fatalf("Error scanning directory: %v", err)
		}
	} else {
		// Show usage
		fmt.Println("Usage:")
		fmt.Println("  driversentinel.exe -common                      # Scan common Windows locations (Admin only)")
		fmt.Println("  driversentinel.exe -path C:\\Path                # Scan specific directory")
		fmt.Println("  driversentinel.exe -path C:\\Path -r             # Scan recursively")
		fmt.Println()
		return
	}

	// Print results
	scanner.PrintResults()
}
