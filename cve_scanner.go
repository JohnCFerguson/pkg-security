package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// Struct to represent the package.json dependencies
type Dependencies struct {
	Dependencies map[string]string `json:"dependencies"`
}

func main() {
	// Get the package.json file path from command-line arguments
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run cve_scanner.go <path/to/package.json>")
		return
	}
	packageJSONPath := os.Args[1]

	// Read and parse the package.json file
	data, err := os.ReadFile(packageJSONPath)
	if err != nil {
		log.Fatalf("Error reading package.json: %v", err)
	}

	nodeVersion, err := getNodeVersion() // Get Node version before main logic
	if err != nil {
		log.Printf("Error checking Node.js version: %v", err)
		// Decide how you want to handle the error here.
		// You could exit the program or proceed with a warning
	} else {
		log.Printf("Active Node.js Version: %s", nodeVersion)
	}

	var dependencies Dependencies
	err = json.Unmarshal(data, &dependencies)
	if err != nil {
		log.Fatalf("Error parsing package.json: %v", err)
	}

	if nodeVersion != "" {
		dependencies.Dependencies["node"] = nodeVersion // Add Node.js version to the dependencies
	}
	f, err := os.OpenFile("cve_scan_results.json", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()
	log.SetOutput(f)

	for dependencyName := range dependencies.Dependencies {
		fmt.Printf("Checking for CVEs for %s...\n", dependencyName)
		checkCVEs(dependencyName)
		fmt.Printf("Finished checking for CVEs for %s\n\n", dependencyName)
	}

}

// Function to query the NIST NVD API and check for CVEs
func checkCVEs(packageName string) {
	var version string
	checkNpmPackage(packageName, &version) // Call to get version

	if version == "" {
		log.Printf("Skipping CVE check for %s: version not found.", packageName)
		return
	}
	// Construct the NVD API URL
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s+%s", packageName, version)

	// Make the API request
	log.Printf("Querying NVD API for %s", packageName)
	log.Printf("URL: %s", url)
	resp, err := http.Get(url)
	if err != nil {
		log.Printf("Error querying NVD API for %s: %v", packageName, err)
		return
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading NVD API response for %s: %v", packageName, err)
		return
	}

	// TODO: Parse the JSON response and extract CVE information
	// This is a placeholder, you need to implement proper JSON parsing
	// and extract relevant CVE details from the response.

	// Example: Check if any CVEs were found
	if len(body) > 0 {
		fmt.Printf("Found potential CVEs for %s:\n", packageName)
		// Print or process the CVE details here
		fmt.Println(string(body)) // Placeholder: Print raw JSON response
	} else {
		fmt.Printf("No CVEs found for %s\n", packageName)
	}
}

func checkNpmPackage(packageName string, version *string) {
	// fetch the package details from npm registry
	npmURL := fmt.Sprintf("https://registry.npmjs.org/%s", packageName)
	npmResp, err := http.Get(npmURL)
	if err != nil {
		log.Printf("Error fetching NPM package details for %s: %v", packageName, err)
		return
	}
	defer npmResp.Body.Close()

	if npmResp.StatusCode != http.StatusOK {
		log.Printf("npm registry returned non-200 status code for %s: %d %s", packageName, npmResp.StatusCode, npmResp.Status)
		return
	}

	var npmData map[string]interface{}
	if err := json.NewDecoder(npmResp.Body).Decode(&npmData); err != nil {
		log.Printf("Error decoding npm JSON response for %s: %v", packageName, err)
		return
	}

	// Get the info that we will need to pass to the nist api above from the npm api
	// we need company, package, version
	// log.Printf("Package name: %s", packageName)
	// log.Printf("Package version: %s", npmPackage.Dependencies[packageName])
	// log.Printf("Package Response: %s", npmResp.Body)

	if versions, ok := npmData["versions"]; ok {
		npmJSON, err := json.MarshalIndent(npmData, "", "  ") // Use json.MarshalIndent
		if err != nil {
			log.Printf("Error formatting npm JSON: %v", err)
		} else {
			log.Printf("NPM Package Data:\n%s", npmJSON) // Print the formatted JSON
		}
		if versionsMap, ok := versions.(map[string]interface{}); ok {
			// Find the latest version
			latestVersion := ""
			for v := range versionsMap {
				if latestVersion == "" || compareVersions(v, latestVersion) > 0 {
					latestVersion = v
				}
			}

			*version = latestVersion // Assign to the version pointer

			if *version == "" {
				log.Printf("Could not determine version for %s", packageName)
				return
			}
			log.Printf("Package Name: %s", packageName)
			log.Printf("Package Version: %s", *version)

			return // Return after finding the latest version
		}
	}

	log.Printf("Could not determine version for %s", packageName)
}

// Function to compare version strings.  Semver library is recommended for production
func compareVersions(v1, v2 string) int {
	// Simple comparison for demonstration.
	// For real-world use, a semver library is highly recommended
	if v1 > v2 {
		return 1
	} else if v1 < v2 {
		return -1
	}
	return 0
}

func getNodeVersion() (string, error) {
	cmd := exec.Command("node", "-v") // Execute the command to check the Node version
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	version := strings.TrimSpace(string(out)) // Clean up the version string
	return version, nil
}
