package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "convert":
		handleConvert()
	case "validate":
		handleValidate()
	case "stats":
		handleStats()
	case "apply":
		handleApply()
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("authz-config - Configuration tool for authz")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  authz-config convert <input> <output>  - Convert between formats")
	fmt.Println("  authz-config validate <file>           - Validate configuration")
	fmt.Println("  authz-config stats <file>              - Show configuration statistics")
	fmt.Println("  authz-config apply <file>              - Apply configuration to engine")
	fmt.Println()
	fmt.Println("Supported formats: .authz, .dsl, .yaml, .yml, .json, .bin")
}

func handleConvert() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: authz-config convert <input> <output>")
		os.Exit(1)
	}

	inputFile := os.Args[2]
	outputFile := os.Args[3]

	cfg, err := loadConfig(inputFile)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := saveConfig(cfg, outputFile); err != nil {
		fmt.Printf("Error saving config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Converted %s -> %s\n", inputFile, outputFile)
	
	inStat, _ := os.Stat(inputFile)
	outStat, _ := os.Stat(outputFile)
	if inStat != nil && outStat != nil {
		reduction := (1 - float64(outStat.Size())/float64(inStat.Size())) * 100
		if reduction > 0 {
			fmt.Printf("Size reduced by %.1f%% (%d -> %d bytes)\n", 
				reduction, inStat.Size(), outStat.Size())
		} else {
			fmt.Printf("Size increased by %.1f%% (%d -> %d bytes)\n", 
				-reduction, inStat.Size(), outStat.Size())
		}
	}
}

func handleValidate() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: authz-config validate <file>")
		os.Exit(1)
	}

	filename := os.Args[2]
	cfg, err := loadConfig(filename)
	if err != nil {
		fmt.Printf("Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	for _, p := range cfg.Policies {
		if p.ID == "" {
			fmt.Printf("Policy missing ID\n")
			os.Exit(1)
		}
		if len(p.Actions) == 0 {
			fmt.Printf("Policy %s has no actions\n", p.ID)
			os.Exit(1)
		}
		if len(p.Resources) == 0 {
			fmt.Printf("Policy %s has no resources\n", p.ID)
			os.Exit(1)
		}
	}

	for _, r := range cfg.Roles {
		if r.ID == "" {
			fmt.Printf("Role missing ID\n")
			os.Exit(1)
		}
	}

	for _, acl := range cfg.ACLs {
		if acl.ID == "" {
			fmt.Printf("ACL missing ID\n")
			os.Exit(1)
		}
		if acl.ResourceID == "" {
			fmt.Printf("ACL %s missing resource_id\n", acl.ID)
			os.Exit(1)
		}
	}

	fmt.Printf("Configuration is valid\n")
	fmt.Printf("  Version: %d\n", cfg.Version)
	fmt.Printf("  Tenants: %d\n", len(cfg.Tenants))
	fmt.Printf("  Policies: %d\n", len(cfg.Policies))
	fmt.Printf("  Roles: %d\n", len(cfg.Roles))
	fmt.Printf("  ACLs: %d\n", len(cfg.ACLs))
	fmt.Printf("  Memberships: %d\n", len(cfg.Memberships))
}

func handleStats() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: authz-config stats <file>")
		os.Exit(1)
	}

	filename := os.Args[2]
	cfg, err := loadConfig(filename)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	stat, _ := os.Stat(filename)
	
	fmt.Println("Configuration Statistics")
	fmt.Println("========================")
	if stat != nil {
		fmt.Printf("File size: %d bytes\n", stat.Size())
	}
	fmt.Printf("Version: %d\n", cfg.Version)
	fmt.Println()
	
	fmt.Println("Components:")
	fmt.Printf("  Tenants:     %d\n", len(cfg.Tenants))
	fmt.Printf("  Policies:    %d\n", len(cfg.Policies))
	fmt.Printf("  Roles:       %d\n", len(cfg.Roles))
	fmt.Printf("  ACLs:        %d\n", len(cfg.ACLs))
	fmt.Printf("  Memberships: %d\n", len(cfg.Memberships))
	fmt.Println()

	if len(cfg.Policies) > 0 {
		allowCount := 0
		denyCount := 0
		for _, p := range cfg.Policies {
			if p.Effect == authz.EffectAllow {
				allowCount++
			} else {
				denyCount++
			}
		}
		fmt.Println("Policy Details:")
		fmt.Printf("  Allow policies: %d\n", allowCount)
		fmt.Printf("  Deny policies:  %d\n", denyCount)
		fmt.Println()
	}

	if len(cfg.Roles) > 0 {
		totalPerms := 0
		for _, r := range cfg.Roles {
			totalPerms += len(r.Permissions)
		}
		fmt.Println("Role Details:")
		fmt.Printf("  Total permissions: %d\n", totalPerms)
		fmt.Printf("  Avg per role:      %.1f\n", float64(totalPerms)/float64(len(cfg.Roles)))
		fmt.Println()
	}

	if len(cfg.Hierarchy) > 0 {
		fmt.Println("Tenant Hierarchy:")
		for child, parent := range cfg.Hierarchy {
			fmt.Printf("  %s -> %s\n", child, parent)
		}
		fmt.Println()
	}

	fmt.Println("Engine Configuration:")
	fmt.Printf("  Decision cache TTL:    %dms\n", cfg.Engine.DecisionCacheTTL)
	fmt.Printf("  Attribute cache TTL:   %dms\n", cfg.Engine.AttributeCacheTTL)
	fmt.Printf("  Audit batch size:      %d\n", cfg.Engine.AuditBatchSize)
	fmt.Printf("  Audit flush interval:  %dms\n", cfg.Engine.AuditFlushInterval)
	fmt.Printf("  Batch worker count:    %d\n", cfg.Engine.BatchWorkerCount)
}

func handleApply() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: authz-config apply <file>")
		os.Exit(1)
	}

	filename := os.Args[2]
	cfg, err := loadConfig(filename)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	engine := authz.NewEngine(
		stores.NewMemoryPolicyStore(),
		stores.NewMemoryRoleStore(),
		stores.NewMemoryACLStore(),
		stores.NewMemoryAuditStore(),
	)

	ctx := context.Background()
	if err := engine.ApplyConfig(ctx, cfg); err != nil {
		fmt.Printf("Error applying config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Configuration applied successfully\n")
	fmt.Printf("  Policies loaded: %d\n", len(cfg.Policies))
	fmt.Printf("  Roles loaded: %d\n", len(cfg.Roles))
	fmt.Printf("  ACLs loaded: %d\n", len(cfg.ACLs))
}

func loadConfig(filename string) (*authz.Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(filename))

	switch ext {
	case ".authz", ".dsl":
		parser := authz.NewDSLParser()
		return parser.Parse(data)
	case ".yaml", ".yml":
		loader := authz.NewConfigLoader()
		return loader.LoadYAML(data)
	case ".json":
		loader := authz.NewConfigLoader()
		return loader.LoadJSON(data)
	case ".bin":
		decoder := authz.NewBinaryDecoder(data)
		return decoder.Decode()
	default:
		return nil, fmt.Errorf("unsupported file format: %s", ext)
	}
}

func saveConfig(cfg *authz.Config, filename string) error {
	ext := strings.ToLower(filepath.Ext(filename))

	var data []byte
	var err error

	switch ext {
	case ".yaml", ".yml":
		data, err = cfg.ToYAML()
	case ".json":
		data, err = cfg.ToJSON()
	case ".bin":
		encoder := authz.NewBinaryEncoder()
		data, err = encoder.Encode(cfg)
	default:
		return fmt.Errorf("unsupported file format: %s", ext)
	}

	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
