package authz

const CurrentConfigVersion uint16 = 1

func MigrateConfig(cfg *Config) (*Config, []ConfigDiagnostic, error) {
	if cfg == nil {
		return nil, nil, (&ConfigValidationError{Diagnostics: []ConfigDiagnostic{diag("error", "nil_config", "configuration is nil", "", "")}})
	}
	var diagnostics []ConfigDiagnostic
	if cfg.Version == 0 {
		cfg.Version = CurrentConfigVersion
		diagnostics = append(diagnostics, diag("warning", "config_version_defaulted", "config version was missing and defaulted to current version", "config", ""))
	}
	if cfg.Version > CurrentConfigVersion {
		return nil, diagnostics, &ConfigValidationError{Diagnostics: []ConfigDiagnostic{diag("error", "unsupported_config_version", "config version is newer than this library supports", "config", "")}}
	}
	if cfg.Hierarchy == nil {
		cfg.Hierarchy = make(map[string]string)
	}
	for _, tenant := range cfg.Tenants {
		if tenant.Parent != "" {
			cfg.Hierarchy[tenant.ID] = tenant.Parent
		}
	}
	return cfg, diagnostics, nil
}
