package scan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"DriverSentinel/repository"
)

// File extensions relevant for drivers
var driverExtensions = map[string]bool{
	".sys": true, // Kernel drivers
	//".dll": true, // DLLs that can act as drivers
	//".exe": true, // Executables related to drivers
}

// ScanResult represents a vulnerable file found
type ScanResult struct {
	FilePath         string
	OriginalFilename string
	SHA256           string
	DriverID         string
	Category         string
	VulnerableDriver repository.KnownVulnerableSample
	Commands         []repository.Commands
	MatchType        string // "filename", "sha256", "both"
}

// Scanner performs scanning of vulnerable files
type Scanner struct {
	repo           *repository.DriverRepository
	hashIndex      map[string][]vulnerableEntry
	filenameIndex  map[string][]vulnerableEntry
	results        []ScanResult
	resultsMutex   sync.Mutex
	scannedFiles   int
	scannedFilesMu sync.Mutex
}

type vulnerableEntry struct {
	driverID string
	category string
	sample   repository.KnownVulnerableSample
	commands []repository.Commands
}

// NewScanner creates a new scanner with optimized indices
func NewScanner(repo *repository.DriverRepository) *Scanner {
	s := &Scanner{
		repo:          repo,
		hashIndex:     make(map[string][]vulnerableEntry),
		filenameIndex: make(map[string][]vulnerableEntry),
		results:       make([]ScanResult, 0),
	}

	// Build indices for fast search
	s.buildIndices()

	return s
}

// buildIndices builds search maps to speed up comparisons
func (s *Scanner) buildIndices() {
	for _, driver := range s.repo.Drivers {
		for _, sample := range driver.KnownVulnerableSamples {
			entry := vulnerableEntry{
				driverID: driver.ID,
				category: driver.Category,
				sample:   sample,
				commands: driver.Commands,
			}

			// Index by SHA256
			if sample.SHA256 != "" {
				hash := strings.ToLower(sample.SHA256)
				s.hashIndex[hash] = append(s.hashIndex[hash], entry)
			}

			// Index by OriginalFilename (case-insensitive)
			if sample.OriginalFilename != "" {
				filename := strings.ToLower(sample.OriginalFilename)
				s.filenameIndex[filename] = append(s.filenameIndex[filename], entry)
			}
		}
	}

	fmt.Printf("[scanner] Indices built: %d hashes, %d filenames\n",
		len(s.hashIndex), len(s.filenameIndex))
	fmt.Printf("[scanner] Valid extension: .sys\n")
}

// ScanDirectory scans a directory recursively
func (s *Scanner) ScanDirectory(rootPath string, recursive bool) error {
	startTime := time.Now()
	fmt.Printf("[scanner] Starting scan of: %s\n", rootPath)

	if recursive {
		err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				fmt.Printf("[scanner] Error accessing %s: %v\n", path, err)
				return nil // continue with other files
			}

			// Ignore directories
			if info.IsDir() {
				return nil
			}

			// Scan only if it's a regular file with valid extension
			if info.Mode().IsRegular() && isDriverFile(path) {
				_ = s.scanFile(path)
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("error during scan: %w", err)
		}
	} else {
		// Non-recursive scan (top level only)
		entries, err := os.ReadDir(rootPath)
		if err != nil {
			return fmt.Errorf("cannot read directory: %w", err)
		}

		for _, entry := range entries {
			if !entry.IsDir() {
				fullPath := filepath.Join(rootPath, entry.Name())
				if isDriverFile(fullPath) {
					_ = s.scanFile(fullPath)
				}
			}
		}
	}

	duration := time.Since(startTime)
	fmt.Printf("\r%s\r", strings.Repeat(" ", 150)) // Clear progress line
	fmt.Printf("[scanner] Scan completed in %v\n", duration)
	fmt.Printf("[scanner] Files scanned: %d\n", s.scannedFiles)
	fmt.Printf("[scanner] Vulnerabilities found: %d\n", len(s.results))

	return nil
}

// ScanFile scans a single file
func (s *Scanner) ScanFile(filePath string) error {
	return s.scanFile(filePath)
}

// scanFile performs the scan of an individual file
// Detection logic by category:
//   - "malicious": reports if name OR hash matches (either)
//   - "vulnerable driver": reports ONLY if name AND hash match (both)
//   - other categories: reports for safety
func (s *Scanner) scanFile(filePath string) error {
	s.incrementScannedFiles()

	// Show file being scanned (clear line completely first)
	fmt.Printf("\r%s\r[scanner] Scanning: %s", strings.Repeat(" ", 120), filePath)

	// Get base filename
	basename := filepath.Base(filePath)

	// First check by filename (fast)
	filenameLower := strings.ToLower(basename)
	filenameMatches := s.filenameIndex[filenameLower]

	// If there are filename matches, calculate hash to verify
	if len(filenameMatches) > 0 {
		hash, err := calculateSHA256(filePath)
		if err != nil {
			// If we can't read the file, report and continue
			if !os.IsPermission(err) {
				fmt.Printf("[scanner] Error calculating hash of %s: %v\n", filePath, err)
			}
			return nil
		}

		hashLower := strings.ToLower(hash)

		// Check each match
		for _, entry := range filenameMatches {
			sampleHashLower := strings.ToLower(entry.sample.SHA256)
			hashMatches := sampleHashLower == hashLower

			matchType := "filename"
			if hashMatches {
				matchType = "both"
			}

			// Reporting logic by category:
			// - "malicious": report if name OR hash matches (either)
			// - "vulnerable driver": report ONLY if name AND hash match (both)
			categoryLower := strings.ToLower(entry.category)
			shouldReport := false

			if categoryLower == "malicious" {
				// Malicious: always report (any match is critical)
				shouldReport = true
			} else if categoryLower == "vulnerable driver" {
				// Vulnerable driver: only report if both match
				shouldReport = hashMatches
			} else {
				// Other categories: report for safety
				shouldReport = true
			}

			if shouldReport {
				// Clear progress line and show detection
				fmt.Printf("\r%s\r", strings.Repeat(" ", 120))
				fmt.Printf("⚠ DETECTED: %s (Type: %s, Category: %s)\n",
					filePath, matchType, entry.category)

				s.addResult(ScanResult{
					FilePath:         filePath,
					OriginalFilename: entry.sample.OriginalFilename,
					SHA256:           hash,
					DriverID:         entry.driverID,
					Category:         entry.category,
					VulnerableDriver: entry.sample,
					Commands:         entry.commands,
					MatchType:        matchType,
				})
			}
		}
	}

	// Also search by pure hash (for renamed files)
	// Only calculate hash if we haven't done it yet
	if len(filenameMatches) == 0 {
		hash, err := calculateSHA256(filePath)
		if err != nil {
			return nil
		}

		hashLower := strings.ToLower(hash)
		hashMatches := s.hashIndex[hashLower]

		for _, entry := range hashMatches {
			// If hash matches but not the name, check category
			categoryLower := strings.ToLower(entry.category)
			shouldReport := false

			if categoryLower == "malicious" {
				// Malicious: always report (hash match is critical)
				shouldReport = true
			} else if categoryLower == "vulnerable driver" {
				// Vulnerable driver: DON'T report (needs name match too)
				// Already checked above, we only get here if name didn't match
				shouldReport = false
			} else {
				// Other categories: report for safety
				shouldReport = true
			}

			if shouldReport {
				// Clear progress line and show detection
				fmt.Printf("\r%s\r", strings.Repeat(" ", 120))
				fmt.Printf("⚠ DETECTED: %s (Type: sha256, Category: %s)\n",
					filePath, entry.category)

				s.addResult(ScanResult{
					FilePath:         filePath,
					OriginalFilename: entry.sample.OriginalFilename,
					SHA256:           hash,
					DriverID:         entry.driverID,
					Category:         entry.category,
					VulnerableDriver: entry.sample,
					Commands:         entry.commands,
					MatchType:        "sha256",
				})
			}
		}
	}

	return nil
}

// calculateSHA256 calculates the SHA256 hash of a file
func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = file.Close()
	}()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// isDriverFile verifies if a file has a relevant extension for drivers
func isDriverFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return driverExtensions[ext]
}

// addResult adds a result in a thread-safe manner
func (s *Scanner) addResult(result ScanResult) {
	s.resultsMutex.Lock()
	defer s.resultsMutex.Unlock()
	s.results = append(s.results, result)
}

// incrementScannedFiles increments the scanned files counter
func (s *Scanner) incrementScannedFiles() {
	s.scannedFilesMu.Lock()
	defer s.scannedFilesMu.Unlock()
	s.scannedFiles++
}

// GetResults returns all found results
func (s *Scanner) GetResults() []ScanResult {
	s.resultsMutex.Lock()
	defer s.resultsMutex.Unlock()
	return s.results
}

// GetScannedFilesCount returns the number of files scanned
func (s *Scanner) GetScannedFilesCount() int {
	s.scannedFilesMu.Lock()
	defer s.scannedFilesMu.Unlock()
	return s.scannedFiles
}

// PrintResults prints the scan results in a readable format
func (s *Scanner) PrintResults() {
	results := s.GetResults()

	if len(results) == 0 {
		fmt.Println("\n✓ No vulnerable drivers found")
		return
	}

	fmt.Printf("\n⚠ ALERT: Found %d vulnerable driver(s)\n", len(results))
	fmt.Println(strings.Repeat("=", 80))

	for i, result := range results {
		fmt.Printf("\n[%d] VULNERABLE FILE DETECTED\n", i+1)
		fmt.Println(strings.Repeat("-", 80))
		fmt.Printf("  Path:          %s\n", result.FilePath)
		fmt.Printf("  SHA256:        %s\n", result.SHA256)
		fmt.Printf("  Match Type:    %s\n", result.MatchType)
		fmt.Printf("  Driver ID:     %s\n", result.DriverID)
		fmt.Printf("  Category:      %s\n", result.Category)
		fmt.Println()
		fmt.Printf("  Vulnerable Driver Details:\n")
		fmt.Printf("    Original:    %s\n", result.VulnerableDriver.OriginalFilename)
		fmt.Printf("    Company:     %s\n", result.VulnerableDriver.Company)
		fmt.Printf("    Product:     %s\n", result.VulnerableDriver.Product)
		fmt.Printf("    Version:     %s\n", result.VulnerableDriver.ProductVersion)
		fmt.Printf("    Description: %s\n", result.VulnerableDriver.Description)

		if result.VulnerableDriver.LoadsDespiteHVCI != "" {
			fmt.Printf("    HVCI:        %s\n", result.VulnerableDriver.LoadsDespiteHVCI)
		}

		// Show exploitation commands if they exist
		if len(result.Commands) > 0 {
			fmt.Println()
			fmt.Printf("  Exploitation Commands:\n")
			for cmdIdx, cmd := range result.Commands {
				fmt.Printf("    ─── Command %d ───\n", cmdIdx+1)
				if cmd.Usecase != "" {
					fmt.Printf("    Use Case:     %s\n", cmd.Usecase)
				}
				if cmd.Privileges != "" {
					fmt.Printf("    Privileges:   %s\n", cmd.Privileges)
				}
				if cmd.OperatingSystem != "" {
					fmt.Printf("    OS:           %s\n", cmd.OperatingSystem)
				}
				if cmd.Description != "" {
					fmt.Printf("    Description:  %s\n", cmd.Description)
				}
				if cmd.Command != "" {
					fmt.Printf("    Command:      %s\n", cmd.Command)
				}
				if len(cmd.Resources) > 0 {
					fmt.Printf("    Resources:    %s\n", strings.Join(cmd.Resources, ", "))
				}
			}
		}
	}

	fmt.Println(strings.Repeat("=", 80))
}

// ScanCommonDriverPaths scans common Windows driver locations
func (s *Scanner) ScanCommonDriverPaths() error {
	commonPaths := []string{
		`C:\Windows\System32\drivers`,
		`C:\Windows\SysWOW64\drivers`,
		`C:\Windows\System32`,
		`C:\Windows\SysWOW64`,
		`c:\Windows\WinSxS`,
		`C:\Windows\System32\DriverStore\FileRepository`,
		`C:\Windows\Boot\`,
		`C:\Windows\System32\boot\`,
		`C:\Windows\System32\Recovery\`,
		`C:\Recovery\WindowsRE\`,
	}

	fmt.Println("[scanner] Scanning common driver locations...")

	for _, path := range commonPaths {
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("[scanner] Scanning: %s\n", path)
			if err := s.ScanDirectory(path, true); err != nil {
				fmt.Printf("[scanner] Error in %s: %v\n", path, err)
			}
		}
	}

	return nil
}
