package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/authz"
	"github.com/oarkflow/authz/stores"
	"github.com/oarkflow/squealx"
	_ "modernc.org/sqlite"
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
	case "plan":
		handlePlan()
	case "apply":
		handleApply()
	case "fmt":
		handleFmt()
	case "sign-keygen":
		handleSignKeygen()
	case "sign":
		handleSign()
	case "verify":
		handleVerify()
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
	fmt.Println("  authz-config plan <file> [--sync]      - Show planned configuration changes")
	fmt.Println("  authz-config apply <file> [--sync] [--dry-run] [--sqlite <db>] - Apply configuration")
	fmt.Println("  authz-config fmt <input> [output]      - Format configuration canonically")
	fmt.Println("  authz-config sign-keygen               - Generate Ed25519 config signing keys")
	fmt.Println("  authz-config sign <file> <private-key> [output] - Sign configuration")
	fmt.Println("  authz-config verify <file> <public-key> - Verify signed configuration")
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
	if err := authz.ValidateConfig(cfg); err != nil {
		fmt.Printf("Invalid configuration: %v\n", err)
		if validationErr, ok := err.(*authz.ConfigValidationError); ok {
			printDiagnostics(validationErr.Diagnostics)
		}
		os.Exit(1)
	}

	fmt.Printf("Configuration is valid\n")
	fmt.Printf("  Version: %d\n", cfg.Version)
	fmt.Printf("  Tenants: %d\n", len(cfg.Tenants))
	fmt.Printf("  Policies: %d\n", len(cfg.Policies))
	fmt.Printf("  Roles: %d\n", len(cfg.Roles))
	fmt.Printf("  ACLs: %d\n", len(cfg.ACLs))
	fmt.Printf("  Memberships: %d\n", len(cfg.Memberships))
	warnings := authz.LintConfig(cfg)
	if len(warnings) > 0 {
		fmt.Println()
		fmt.Println("Warnings:")
		printDiagnostics(warnings)
	}
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
		fmt.Println("Usage: authz-config apply <file> [--sync] [--dry-run]")
		os.Exit(1)
	}

	filename := os.Args[2]
	cliOpts := parseApplyOptions(os.Args[3:])
	opts := cliOpts.ConfigApplyOptions
	cfg, err := loadConfig(filename)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}
	if err := authz.ValidateConfig(cfg); err != nil {
		fmt.Printf("Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	engine, iamStores, cleanup, err := newCLIEngine(cliOpts.SQLitePath)
	if err != nil {
		fmt.Printf("Error opening stores: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()

	ctx := context.Background()
	if opts.Mode == authz.ApplyModeSync || opts.DryRun {
		plan, err := engine.PlanConfigApply(ctx, cfg, opts)
		if err != nil {
			fmt.Printf("Error planning config: %v\n", err)
			os.Exit(1)
		}
		printPlan(plan)
		if err := engine.ApplyConfigPlan(ctx, plan); err != nil {
			fmt.Printf("Error applying config plan: %v\n", err)
			os.Exit(1)
		}
		if opts.DryRun {
			fmt.Printf("Dry run completed; no changes applied\n")
			return
		}
	} else {
		if err := engine.ApplyConfig(ctx, cfg); err != nil {
			fmt.Printf("Error applying config: %v\n", err)
			os.Exit(1)
		}
	}
	if !opts.DryRun {
		if err := authz.ApplyConfigIAM(ctx, cfg, iamStores); err != nil {
			fmt.Printf("Error applying IAM config: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Configuration applied successfully\n")
	fmt.Printf("  Policies loaded: %d\n", len(cfg.Policies))
	fmt.Printf("  Roles loaded: %d\n", len(cfg.Roles))
	fmt.Printf("  ACLs loaded: %d\n", len(cfg.ACLs))
}

func handlePlan() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: authz-config plan <file> [--sync]")
		os.Exit(1)
	}
	filename := os.Args[2]
	cliOpts := parseApplyOptions(os.Args[3:])
	opts := cliOpts.ConfigApplyOptions
	opts.DryRun = true
	cfg, err := loadConfig(filename)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}
	engine, _, cleanup, err := newCLIEngine(cliOpts.SQLitePath)
	if err != nil {
		fmt.Printf("Error opening stores: %v\n", err)
		os.Exit(1)
	}
	defer cleanup()
	plan, err := engine.PlanConfigApply(context.Background(), cfg, opts)
	if err != nil {
		fmt.Printf("Error planning config: %v\n", err)
		os.Exit(1)
	}
	printPlan(plan)
}

type cliApplyOptions struct {
	authz.ConfigApplyOptions
	SQLitePath string
}

func parseApplyOptions(args []string) cliApplyOptions {
	opts := cliApplyOptions{ConfigApplyOptions: authz.ConfigApplyOptions{Mode: authz.ApplyModeUpsert}}
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--sync":
			opts.Mode = authz.ApplyModeSync
		case "--dry-run":
			opts.DryRun = true
		case "--sqlite":
			if i+1 >= len(args) {
				fmt.Println("--sqlite requires a database path")
				os.Exit(1)
			}
			i++
			opts.SQLitePath = args[i]
		default:
			fmt.Printf("Unknown option: %s\n", arg)
			os.Exit(1)
		}
	}
	return opts
}

func newCLIEngine(sqlitePath string) (*authz.Engine, authz.ConfigIAMStores, func(), error) {
	if sqlitePath == "" {
		tenantStore := stores.NewMemoryTenantStore()
		userStore := stores.NewMemoryUserStore()
		groupStore := stores.NewMemoryGroupStore()
		scopeStore := stores.NewMemoryScopeStore()
		saStore := stores.NewMemoryServiceAccountStore()
		invStore := stores.NewMemoryInvitationStore()
		apiKeyStore := stores.NewMemoryAPIKeyStore()
		boundaryStore := stores.NewMemoryPermissionBoundaryStore()
		engine := authz.NewEngine(
			stores.NewMemoryPolicyStore(),
			stores.NewMemoryRoleStore(),
			stores.NewMemoryACLStore(),
			stores.NewMemoryAuditStore(),
			authz.WithTenantStore(tenantStore),
			authz.WithRoleMembershipStore(stores.NewMemoryRoleMembershipStore()),
		)
		return engine, authz.ConfigIAMStores{Users: userStore, Groups: groupStore, Scopes: scopeStore, ServiceAccounts: saStore, Invitations: invStore, APIKeys: apiKeyStore, PermissionBoundaries: boundaryStore}, func() {}, nil
	}
	sqlDB, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return nil, authz.ConfigIAMStores{}, nil, err
	}
	db := squealx.NewDb(sqlDB, "sqlite", "authz")
	if err := stores.Migrate(db); err != nil {
		sqlDB.Close()
		return nil, authz.ConfigIAMStores{}, nil, err
	}
	auditStore, err := stores.NewSQLAuditStore(db)
	if err != nil {
		sqlDB.Close()
		return nil, authz.ConfigIAMStores{}, nil, err
	}
	engine := authz.NewEngine(
		stores.NewSQLPolicyStore(db),
		stores.NewSQLRoleStore(db),
		stores.NewSQLACLStore(db),
		auditStore,
		authz.WithTenantStore(stores.NewSQLTenantStore(db)),
		authz.WithRoleMembershipStore(stores.NewSQLRoleMembershipStore(db)),
	)
	iamStores := authz.ConfigIAMStores{
		Users:                stores.NewSQLUserStore(db),
		Groups:               stores.NewSQLGroupStore(db),
		Scopes:               stores.NewSQLScopeStore(db),
		ServiceAccounts:      stores.NewSQLServiceAccountStore(db),
		Invitations:          stores.NewSQLInvitationStore(db),
		APIKeys:              stores.NewSQLAPIKeyStore(db),
		PermissionBoundaries: stores.NewSQLPermissionBoundaryStore(db),
	}
	return engine, iamStores, func() { sqlDB.Close() }, nil
}

func printPlan(plan *authz.ConfigApplyPlan) {
	mode := plan.Options.Mode
	if mode == "" {
		mode = authz.ApplyModeUpsert
	}
	fmt.Printf("Configuration apply plan\n")
	fmt.Printf("  Mode: %s\n", mode)
	fmt.Printf("  Dry run: %t\n", plan.Options.DryRun)
	fmt.Printf("  Operations: %d\n", len(plan.Operations))
	for _, op := range plan.Operations {
		if op.TenantID != "" {
			fmt.Printf("  - %s %s %s tenant=%s", op.Action, op.EntityType, op.EntityID, op.TenantID)
		} else {
			fmt.Printf("  - %s %s %s", op.Action, op.EntityType, op.EntityID)
		}
		if op.Reason != "" {
			fmt.Printf(" (%s)", op.Reason)
		}
		fmt.Println()
	}
	if len(plan.Diagnostics) > 0 {
		fmt.Println("Diagnostics:")
		printDiagnostics(plan.Diagnostics)
	}
}

func printDiagnostics(diagnostics []authz.ConfigDiagnostic) {
	for _, d := range diagnostics {
		entity := ""
		if d.EntityType != "" || d.EntityID != "" {
			entity = fmt.Sprintf(" [%s:%s]", d.EntityType, d.EntityID)
		}
		fmt.Printf("  - %s %s%s: %s\n", d.Severity, d.Code, entity, d.Message)
	}
}

func handleFmt() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: authz-config fmt <input> [output]")
		os.Exit(1)
	}
	cfg, err := loadConfig(os.Args[2])
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}
	data, err := authz.NewDSLEncoder().Encode(cfg)
	if err != nil {
		fmt.Printf("Error formatting config: %v\n", err)
		os.Exit(1)
	}
	if len(os.Args) >= 4 {
		if err := os.WriteFile(os.Args[3], data, 0644); err != nil {
			fmt.Printf("Error writing config: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Print(string(data))
}

func handleSignKeygen() {
	pub, priv, err := authz.GenerateConfigSigningKey()
	if err != nil {
		fmt.Printf("Error generating signing key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("PublicKey: %s\n", pub)
	fmt.Printf("PrivateKey: %s\n", priv)
}

func handleSign() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: authz-config sign <file> <private-key> [output]")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		os.Exit(1)
	}
	sig, err := authz.SignConfig(data, os.Args[3])
	if err != nil {
		fmt.Printf("Error signing config: %v\n", err)
		os.Exit(1)
	}
	signed := authz.AppendConfigSignature(data, sig)
	if len(os.Args) >= 5 {
		if err := os.WriteFile(os.Args[4], signed, 0644); err != nil {
			fmt.Printf("Error writing signed config: %v\n", err)
			os.Exit(1)
		}
		return
	}
	fmt.Print(string(signed))
}

func handleVerify() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: authz-config verify <file> <public-key>")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Printf("Error reading config: %v\n", err)
		os.Exit(1)
	}
	if err := authz.VerifyConfigSignature(data, os.Args[3]); err != nil {
		fmt.Printf("Signature verification failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Signature verified")
}

func loadConfig(filename string) (*authz.Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(filename))

	var cfg *authz.Config
	switch ext {
	case ".authz", ".dsl":
		parser := authz.NewDSLParser()
		cfg, err = parser.ParseFile(filename)
	case ".yaml", ".yml":
		loader := authz.NewConfigLoader()
		cfg, err = loader.LoadYAML(data)
	case ".json":
		loader := authz.NewConfigLoader()
		cfg, err = loader.LoadJSON(data)
	case ".bin":
		decoder := authz.NewBinaryDecoder(data)
		cfg, err = decoder.Decode()
	default:
		return nil, fmt.Errorf("unsupported file format: %s", ext)
	}
	if err != nil {
		return nil, err
	}
	cfg, _, err = authz.MigrateConfig(cfg)
	return cfg, err
}

func saveConfig(cfg *authz.Config, filename string) error {
	ext := strings.ToLower(filepath.Ext(filename))

	var data []byte
	var err error

	switch ext {
	case ".authz", ".dsl":
		encoder := authz.NewDSLEncoder()
		data, err = encoder.Encode(cfg)
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
