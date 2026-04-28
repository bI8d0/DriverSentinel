package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func main() {
	// Get the current directory
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Printf("Error getting the current directory: %v\n", err)
		return
	}

	// Create the build directory if it doesn't exist
	buildDir := filepath.Join(currentDir, "build")
	if err := os.MkdirAll(buildDir, 0755); err != nil {
		fmt.Printf("Error creating the build directory: %v\n", err)
		return
	}

	// Executable name
	executableName := "driversentinel"

	// File to compile
	filename := "main.go"

	// Build for Windows
	fmt.Println("Building for Windows...")
	if err := buildForWindows(filepath.Join(buildDir, executableName+".exe"), filename, currentDir); err != nil {
		fmt.Printf("Error building for Windows: %v\n", err)
	}

	fmt.Println("Build completed. Binaries are located in the 'build' directory.")
}

func buildForWindows(outputName, filename, currentDir string) error {
	// Build for Windows
	cmd := exec.Command("go", "build", "-o", outputName, filename)
	cmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH=amd64",
	)
	cmd.Dir = currentDir

	buildOutput, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("build error: %v\nOutput: %s", err, buildOutput)
	}

	fmt.Printf("Windows build completed.\n")

	// Verify the executable was created
	if _, err := os.Stat(outputName); os.IsNotExist(err) {
		return fmt.Errorf("the Windows executable was not generated correctly")
	}

	return nil
}
