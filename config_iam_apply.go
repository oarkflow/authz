package authz

import (
	"context"
	"time"
)

type ConfigIAMStores struct {
	Users                UserStore
	Groups               GroupStore
	Scopes               ScopeStore
	ServiceAccounts      ServiceAccountStore
	Invitations          InvitationStore
	APIKeys              APIKeyStore
	PermissionBoundaries PermissionBoundaryStore
}

func ApplyConfigIAM(ctx context.Context, cfg *Config, stores ConfigIAMStores) error {
	now := time.Now()
	if stores.Users != nil {
		for _, u := range cfg.Users {
			if u.CreatedAt.IsZero() {
				u.CreatedAt = now
			}
			u.UpdatedAt = now
			if _, err := stores.Users.GetUser(ctx, u.ID); err == nil {
				if err := stores.Users.UpdateUser(ctx, u); err != nil {
					return err
				}
			} else if err := stores.Users.CreateUser(ctx, u); err != nil {
				return err
			}
		}
	}
	if stores.Groups != nil {
		for _, g := range cfg.Groups {
			if g.CreatedAt.IsZero() {
				g.CreatedAt = now
			}
			g.UpdatedAt = now
			if _, err := stores.Groups.GetGroup(ctx, g.ID); err == nil {
				if err := stores.Groups.UpdateGroup(ctx, g); err != nil {
					return err
				}
			} else if err := stores.Groups.CreateGroup(ctx, g); err != nil {
				return err
			}
		}
	}
	if stores.Scopes != nil {
		for _, s := range cfg.Scopes {
			if s.CreatedAt.IsZero() {
				s.CreatedAt = now
			}
			if _, err := stores.Scopes.GetScope(ctx, s.ID); err == nil {
				if err := stores.Scopes.UpdateScope(ctx, s); err != nil {
					return err
				}
			} else if err := stores.Scopes.CreateScope(ctx, s); err != nil {
				return err
			}
		}
	}
	if stores.ServiceAccounts != nil {
		for _, sa := range cfg.ServiceAccounts {
			if sa.CreatedAt.IsZero() {
				sa.CreatedAt = now
			}
			sa.UpdatedAt = now
			if _, err := stores.ServiceAccounts.GetServiceAccount(ctx, sa.ID); err == nil {
				if err := stores.ServiceAccounts.UpdateServiceAccount(ctx, sa); err != nil {
					return err
				}
			} else if err := stores.ServiceAccounts.CreateServiceAccount(ctx, sa); err != nil {
				return err
			}
		}
	}
	if stores.Invitations != nil {
		for _, inv := range cfg.Invitations {
			if inv.CreatedAt.IsZero() {
				inv.CreatedAt = now
			}
			if _, err := stores.Invitations.GetInvitation(ctx, inv.ID); err == nil {
				if err := stores.Invitations.UpdateInvitation(ctx, inv); err != nil {
					return err
				}
			} else if err := stores.Invitations.CreateInvitation(ctx, inv); err != nil {
				return err
			}
		}
	}
	if stores.APIKeys != nil {
		for _, key := range cfg.APIKeys {
			if key.CreatedAt.IsZero() {
				key.CreatedAt = now
			}
			if err := stores.APIKeys.CreateAPIKey(ctx, key); err != nil {
				return err
			}
		}
	}
	if stores.PermissionBoundaries != nil {
		for _, boundary := range cfg.PermissionBoundaries {
			if boundary.CreatedAt.IsZero() {
				boundary.CreatedAt = now
			}
			if _, err := stores.PermissionBoundaries.GetBoundary(ctx, boundary.ID); err == nil {
				if err := stores.PermissionBoundaries.UpdateBoundary(ctx, boundary); err != nil {
					return err
				}
			} else if err := stores.PermissionBoundaries.CreateBoundary(ctx, boundary); err != nil {
				return err
			}
		}
	}
	return nil
}
