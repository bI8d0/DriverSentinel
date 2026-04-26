package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	driversURL      = "https://www.loldrivers.io/api/drivers.json"
	driversFileName = "drivers.json"
	etagFileName    = "drivers.etag"
)

// ── loldrivers.io JSON structs ────────────────────────────────────────────────

type Acknowledgement struct {
	Handle string `json:"Handle"`
	Person string `json:"Person"`
}

type Commands struct {
	Command         string   `json:"Command"`
	Description     string   `json:"Description"`
	OperatingSystem string   `json:"OperatingSystem"`
	Privileges      string   `json:"Privileges"`
	Usecase         string   `json:"Usecase"`
	Resources       []string `json:"Resources"`
}

type KnownVulnerableSample struct {
	Filename         string   `json:"Filename"`
	LoadsDespiteHVCI string   `json:"LoadsDespiteHVCI"`
	Company          string   `json:"Company"`
	Description      string   `json:"Description"`
	Product          string   `json:"Product"`
	ProductVersion   string   `json:"ProductVersion"`
	FileVersion      string   `json:"FileVersion"`
	MachineType      string   `json:"MachineType"`
	OriginalFilename string   `json:"OriginalFilename"`
	FileDescription  string   `json:"FileDescription"`
	InternalName     string   `json:"InternalName"`
	Copyright        string   `json:"Copyright"`
	Authentihash     string   `json:"Authentihash"`
	MD5              string   `json:"MD5"`
	SHA1             string   `json:"SHA1"`
	SHA256           string   `json:"SHA256"`
	Signature        []string `json:"Signature"`
	Date             string   `json:"Date"`
}

type Detection struct {
	Name string `json:"Name"`
	Type string `json:"Type"`
}

// Driver holds known fields with strong typing plus an Extra map that
// automatically captures any new or unknown fields from the JSON.
// All fields are optional: null, {}, [] or missing values will not break parsing.
type Driver struct {
	ID                     string                  `json:"Id"`
	Tags                   []string                `json:"Tags"`
	Verified               string                  `json:"Verified"`
	Author                 string                  `json:"Author"`
	Created                string                  `json:"Created"`
	MitreID                string                  `json:"MitreID"`
	Category               string                  `json:"Category"`
	Commands               []Commands              `json:"Commands"`
	Detection              []Detection             `json:"Detection"`
	Acknowledgement        []Acknowledgement       `json:"Acknowledgement"`
	KnownVulnerableSamples []KnownVulnerableSample `json:"KnownVulnerableSamples"`

	// Extra captures any unknown or future fields from the JSON automatically.
	Extra map[string]json.RawMessage `json:"-"`
}

// knownDriverKeys lists the fields already handled with strong typing.
var knownDriverKeys = map[string]bool{
	"Id": true, "Tags": true, "Verified": true, "Author": true,
	"Created": true, "MitreID": true, "Category": true,
	"Commands": true, "Detection": true, "Acknowledgement": true,
	"KnownVulnerableSamples": true,
}

// UnmarshalJSON parses known fields with strong types and stores unknown
// fields in Extra. Tolerates null, {}, [] or missing fields without errors.
func (d *Driver) UnmarshalJSON(data []byte) error {
	// Alias to avoid infinite recursion
	type KnownFields struct {
		ID                     string          `json:"Id"`
		Tags                   []string        `json:"Tags"`
		Verified               string          `json:"Verified"`
		Author                 string          `json:"Author"`
		Created                string          `json:"Created"`
		MitreID                string          `json:"MitreID"`
		Category               string          `json:"Category"`
		Commands               json.RawMessage `json:"Commands"`
		Detection              json.RawMessage `json:"Detection"`
		Acknowledgement        json.RawMessage `json:"Acknowledgement"`
		KnownVulnerableSamples json.RawMessage `json:"KnownVulnerableSamples"`
	}

	var known KnownFields
	if err := json.Unmarshal(data, &known); err != nil {
		return err
	}

	d.ID = known.ID
	d.Tags = known.Tags
	d.Verified = known.Verified
	d.Author = known.Author
	d.Created = known.Created
	d.MitreID = known.MitreID
	d.Category = known.Category
	d.Commands = parseAsSlice[Commands](known.Commands)
	d.Detection = parseAsSlice[Detection](known.Detection)
	d.Acknowledgement = parseAsSlice[Acknowledgement](known.Acknowledgement)
	d.KnownVulnerableSamples = parseAsSlice[KnownVulnerableSample](known.KnownVulnerableSamples)

	// Parse the full JSON into a generic map to capture unknown fields
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}

	d.Extra = make(map[string]json.RawMessage)
	for k, v := range all {
		if !knownDriverKeys[k] {
			d.Extra[k] = v
		}
	}

	return nil
}

// parseAsSlice converts a RawMessage into []T tolerating:
// null, {}, [], a single object or an array. Returns nil without error if it cannot parse.
func parseAsSlice[T any](raw json.RawMessage) []T {
	if len(raw) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "null" || trimmed == "{}" || trimmed == "[]" || trimmed == "" {
		return nil
	}
	// Try as array first
	var arr []T
	if err := json.Unmarshal(raw, &arr); err == nil {
		return arr
	}
	// Try as single object and wrap it in a slice
	var single T
	if err := json.Unmarshal(raw, &single); err == nil {
		return []T{single}
	}
	return nil
}

// ── DriverRepository ──────────────────────────────────────────────────────────

type DriverRepository struct {
	filePath string
	etagPath string
	Drivers  []Driver
}

// NewDriverRepository creates the repository and synchronizes it if needed.
func NewDriverRepository() (*DriverRepository, error) {
	dir, err := executableDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine executable directory: %w", err)
	}

	repo := &DriverRepository{
		filePath: filepath.Join(dir, driversFileName),
		etagPath: filepath.Join(dir, etagFileName),
	}

	if err := repo.Load(); err != nil {
		return nil, err
	}

	return repo, nil
}

// Load checks for remote changes and downloads the file if needed.
func (r *DriverRepository) Load() error {
	changed, reason, remoteETag, err := r.hasRemoteChanged()
	if err != nil {
		if _, statErr := os.Stat(r.filePath); statErr == nil {
			fmt.Printf("[repository] Cannot check remote (%v) — using local copy\n", err)
			return r.loadFromDisk()
		}
		return fmt.Errorf("no local copy and remote check failed: %w", err)
	}

	if changed {
		fmt.Printf("[repository] Update detected (%s) — downloading...\n", reason)
		if err := r.download(remoteETag); err != nil {
			return fmt.Errorf("download failed: %w", err)
		}
	} else {
		fmt.Println("[repository] Local copy is up to date")
	}

	return r.loadFromDisk()
}

// hasRemoteChanged sends a HEAD request and compares the ETag.
// Returns: (changed, reason, remoteETag, error)
func (r *DriverRepository) hasRemoteChanged() (bool, string, string, error) {
	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Head(driversURL)
	if err != nil {
		return false, "", "", fmt.Errorf("HEAD request failed: %w", err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		fmt.Printf("[repository] warning: closing HEAD body: %v\n", closeErr)
	}

	if resp.StatusCode != http.StatusOK {
		return false, "", "", fmt.Errorf("unexpected HEAD status: %s", resp.Status)
	}

	remoteETag := strings.Trim(resp.Header.Get("ETag"), `"`)

	// ── Case A: server provides ETag ─────────────────────────────────────────
	if remoteETag != "" {
		localETag := r.readLocalETag()
		if localETag == "" {
			return true, "no local ETag found", remoteETag, nil
		}
		if localETag != remoteETag {
			return true, fmt.Sprintf("ETag changed (%s → %s)", localETag, remoteETag), remoteETag, nil
		}
		return false, "", remoteETag, nil
	}

	// ── Case B: no ETag → fall back to SHA256 ────────────────────────────────
	fmt.Println("[repository] Server has no ETag, falling back to SHA256 comparison...")

	if _, statErr := os.Stat(r.filePath); os.IsNotExist(statErr) {
		return true, "local file missing", "", nil
	}

	remoteHash, err := r.fetchRemoteSHA256(client)
	if err != nil {
		return false, "", "", fmt.Errorf("SHA256 fetch failed: %w", err)
	}

	localHash, err := r.localSHA256()
	if err != nil {
		return true, "cannot read local hash", remoteHash, nil
	}

	if localHash != remoteHash {
		return true, fmt.Sprintf("SHA256 changed (%s… → %s…)", localHash[:8], remoteHash[:8]), remoteHash, nil
	}

	return false, "", remoteHash, nil
}

// fetchRemoteSHA256 downloads the full file and computes its SHA256.
// Only used when the server does not provide an ETag.
func (r *DriverRepository) fetchRemoteSHA256(client *http.Client) (string, error) {
	resp, err := client.Get(driversURL)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("[repository] warning: closing SHA256 body: %v\n", closeErr)
		}
	}()

	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// localSHA256 computes the SHA256 of the local drivers file.
func (r *DriverRepository) localSHA256() (string, error) {
	f, err := os.Open(r.filePath)
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			fmt.Printf("[repository] warning: closing local file: %v\n", closeErr)
		}
	}()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// download fetches the JSON from the remote URL and saves ETag or SHA256 as a local reference.
func (r *DriverRepository) download(newETag string) error {
	client := &http.Client{Timeout: 60 * time.Second}

	resp, err := client.Get(driversURL)
	if err != nil {
		return fmt.Errorf("GET failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("[repository] warning: closing download body: %v\n", closeErr)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected GET status: %s", resp.Status)
	}

	// Atomic write: write to .tmp first, then rename to final destination
	tmpPath := r.filePath + ".tmp"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("cannot create temp file: %w", err)
	}

	h := sha256.New()
	writer := io.MultiWriter(tmpFile, h)

	if _, err := io.Copy(writer, resp.Body); err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			fmt.Printf("[repository] warning: closing tmp on error: %v\n", closeErr)
		}
		if removeErr := os.Remove(tmpPath); removeErr != nil {
			fmt.Printf("[repository] warning: removing tmp on error: %v\n", removeErr)
		}
		return fmt.Errorf("write error: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("cannot close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, r.filePath); err != nil {
		if removeErr := os.Remove(tmpPath); removeErr != nil {
			fmt.Printf("[repository] warning: removing tmp after failed rename: %v\n", removeErr)
		}
		return fmt.Errorf("cannot replace drivers file: %w", err)
	}

	// Store remote ETag; if none was provided, store the SHA256 of the downloaded file
	ref := newETag
	if ref == "" {
		ref = hex.EncodeToString(h.Sum(nil))
	}
	r.saveLocalETag(ref)

	shortRef := ref
	if len(shortRef) > 8 {
		shortRef = shortRef[:8]
	}
	fmt.Printf("[repository] Saved → %s  (ref: %s…)\n", r.filePath, shortRef)
	return nil
}

// loadFromDisk reads and parses the JSON file from disk.
func (r *DriverRepository) loadFromDisk() error {
	data, err := os.ReadFile(r.filePath)
	if err != nil {
		return fmt.Errorf("cannot read drivers file: %w", err)
	}

	if err := json.Unmarshal(data, &r.Drivers); err != nil {
		return fmt.Errorf("cannot parse drivers JSON: %w", err)
	}

	fmt.Printf("[repository] Loaded %d drivers\n", len(r.Drivers))
	return nil
}

// ── ETag helpers ──────────────────────────────────────────────────────────────

func (r *DriverRepository) readLocalETag() string {
	data, err := os.ReadFile(r.etagPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (r *DriverRepository) saveLocalETag(etag string) {
	if err := os.WriteFile(r.etagPath, []byte(etag), 0644); err != nil {
		fmt.Printf("[repository] warning: cannot save etag: %v\n", err)
	}
}

// executableDir returns the directory of the running binary.
func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	return filepath.Dir(resolved), nil
}
