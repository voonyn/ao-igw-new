package oidc

import "encoding/json"

// ScopeBody is the body of one scope write. The console sends the whole form on
// a create and on a write, so every field is present and the write replaces
// what the row said.
//
// The name is the scope string a client asks for. An OAuth scope is a
// space-delimited token of printable ASCII, so a space, a quote, and a backslash
// are refused: a name carrying one of them could not be requested at all. The
// name of a builtin scope is locked, and the service leaves it alone.
type ScopeBody struct {
	Name        string `json:"name" validate:"required,max=191,printascii,excludesall=\" \\"`
	DisplayName string `json:"displayName" validate:"max=255"`
	Description string `json:"description" validate:"max=2000"`

	IsEnabled bool `json:"isEnabled"`
	IsDefault bool `json:"isDefault"`
}

// ScopeView is one scope as the console reads it. MapperCount is the number of
// claims the scope releases, so the list names the size of each scope without a
// request per row.
//
// IsBuiltin marks a scope the migration seeded. Its name is locked and it cannot
// be deleted, and the console renders both facts from this field.
type ScopeView struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`

	IsEnabled bool `json:"isEnabled"`
	IsDefault bool `json:"isDefault"`
	IsBuiltin bool `json:"isBuiltin"`

	MapperCount int `json:"mapperCount"`
}

func scopeView(row ScopeRow) ScopeView {
	return ScopeView{
		ID:          row.ID,
		Name:        row.Name,
		DisplayName: row.DisplayName,
		Description: row.Description,
		IsEnabled:   row.IsEnabled,
		IsDefault:   row.IsDefault,
		IsBuiltin:   row.IsBuiltin,
		MapperCount: row.MapperCount,
	}
}

// MapperBody is the body of one claim mapper write. The console sends the whole
// form on a create and on a write, so every field is present and the write
// replaces what the row said.
//
// SourceKey selects where the value comes from, and it is never interpolated
// into SQL: a standard attribute resolves through the whitelist in
// claims_service.go, and a bag key reads a parsed JSON column.
//
// SourceValue is the value of a static mapper, and it is ignored by every other
// source type. It is any JSON the operator wrote, so the token releases the
// shape they typed.
type MapperBody struct {
	ClaimName  string `json:"claimName" validate:"required,max=191,printascii,excludesall=\" \\"`
	SourceType int    `json:"sourceType" validate:"required,min=1,max=4"`
	SourceKey  string `json:"sourceKey" validate:"max=191"`

	SourceValue any `json:"sourceValue"`

	InIDToken     bool `json:"inIdToken"`
	InUserInfo    bool `json:"inUserInfo"`
	InAccessToken bool `json:"inAccessToken"`
}

// MapperView is one claim mapper as the console reads it. SourceValue is absent
// for every source type but the static one, which is the only one that carries a
// value instead of a key.
type MapperView struct {
	ID        string `json:"id"`
	ScopeID   string `json:"scopeId"`
	ClaimName string `json:"claimName"`

	SourceType  int    `json:"sourceType"`
	SourceKey   string `json:"sourceKey"`
	SourceValue any    `json:"sourceValue,omitempty"`

	InIDToken     bool `json:"inIdToken"`
	InUserInfo    bool `json:"inUserInfo"`
	InAccessToken bool `json:"inAccessToken"`
}

// mapperView reads the stored row back. A source value that does not parse is
// answered as absent: the column is written by this API alone, so a value that
// is not JSON is a repair job and not something the console can act on.
func mapperView(row ClaimMapperRow) MapperView {
	view := MapperView{
		ID:            row.ID,
		ScopeID:       row.ScopeID,
		ClaimName:     row.ClaimName,
		SourceType:    row.SourceType,
		SourceKey:     row.SourceKey,
		InIDToken:     row.InIDToken,
		InUserInfo:    row.InUserInfo,
		InAccessToken: row.InAccessToken,
	}
	if row.SourceValue != "" {
		var value any
		if err := json.Unmarshal([]byte(row.SourceValue), &value); err == nil {
			view.SourceValue = value
		}
	}
	return view
}
