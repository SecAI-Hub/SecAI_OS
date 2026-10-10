package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type gatewayRole string

const (
	roleEvaluator     gatewayRole = "evaluator"
	roleObserver      gatewayRole = "observer"
	roleAdministrator gatewayRole = "administrator"
)

type credentialDefinition struct {
	Identity  string        `yaml:"identity"`
	TokenPath string        `yaml:"token_path"`
	Roles     []gatewayRole `yaml:"roles"`
}

type credentialDocument struct {
	Version     int                    `yaml:"version"`
	Credentials []credentialDefinition `yaml:"credentials"`
}

type credentialPrincipal struct {
	identity    string
	tokenDigest [sha256.Size]byte
	roles       map[gatewayRole]struct{}
}

type credentialSet struct {
	principals []credentialPrincipal
}

type credentialContextKey struct{}

var credentialIdentityPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

const maxCredentialTokenSize = 4096

func loadCredentialSet() (*credentialSet, error) {
	if path := os.Getenv("CREDENTIALS_CONFIG_PATH"); path != "" {
		if !filepath.IsAbs(path) {
			return nil, errors.New("credential configuration path must be absolute")
		}
		return loadCredentialSetFile(path)
	}
	service, err := loadServiceToken()
	if err != nil {
		return nil, err
	}
	admin, err := loadAdminToken()
	if err != nil {
		return nil, err
	}
	return newCredentialSet([]credentialPrincipal{
		{identity: "service", tokenDigest: sha256.Sum256([]byte(service)), roles: roleMap(roleEvaluator, roleObserver)},
		{identity: "admin", tokenDigest: sha256.Sum256([]byte(admin)), roles: roleMap(roleAdministrator)},
	})
}

func loadCredentialSetFile(path string) (*credentialSet, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("credential configuration path must be absolute")
	}
	data, err := readTrustedCredentialFile(path, "credential configuration", 64<<10, 0o022)
	if err != nil {
		return nil, err
	}
	var document credentialDocument
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse credential configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("credential configuration must contain exactly one YAML document")
	}
	if document.Version != 1 || len(document.Credentials) < 2 || len(document.Credentials) > 256 {
		return nil, errors.New("credential configuration requires version 1 and 2 to 256 credentials")
	}
	principals := make([]credentialPrincipal, 0, len(document.Credentials))
	for _, definition := range document.Credentials {
		if !credentialIdentityPattern.MatchString(definition.Identity) {
			return nil, errors.New("credential identity is invalid")
		}
		if !filepath.IsAbs(definition.TokenPath) {
			return nil, fmt.Errorf("credential %q token_path must be absolute", definition.Identity)
		}
		token, err := loadTokenCredentialPath(definition.TokenPath, "credential "+definition.Identity)
		if err != nil {
			return nil, err
		}
		roles := make(map[gatewayRole]struct{}, len(definition.Roles))
		for _, role := range definition.Roles {
			if role != roleEvaluator && role != roleObserver && role != roleAdministrator {
				return nil, fmt.Errorf("credential %q has unknown role", definition.Identity)
			}
			roles[role] = struct{}{}
		}
		if len(roles) == 0 {
			return nil, fmt.Errorf("credential %q has no roles", definition.Identity)
		}
		if _, admin := roles[roleAdministrator]; admin && len(roles) != 1 {
			return nil, fmt.Errorf("credential %q cannot combine administrator with other roles", definition.Identity)
		}
		principals = append(principals, credentialPrincipal{identity: definition.Identity, tokenDigest: token, roles: roles})
	}
	return newCredentialSet(principals)
}

func newCredentialSet(principals []credentialPrincipal) (*credentialSet, error) {
	identities := make(map[string]struct{}, len(principals))
	hasEvaluator, hasAdmin := false, false
	for i := range principals {
		principal := &principals[i]
		if !credentialIdentityPattern.MatchString(principal.identity) || len(principal.roles) == 0 {
			return nil, errors.New("credential principal is invalid")
		}
		if _, admin := principal.roles[roleAdministrator]; admin && len(principal.roles) != 1 {
			return nil, fmt.Errorf("credential %q cannot combine administrator with other roles", principal.identity)
		}
		if _, exists := identities[principal.identity]; exists {
			return nil, fmt.Errorf("duplicate credential identity %q", principal.identity)
		}
		identities[principal.identity] = struct{}{}
		if _, ok := principal.roles[roleEvaluator]; ok {
			hasEvaluator = true
		}
		if _, ok := principal.roles[roleAdministrator]; ok {
			hasAdmin = true
		}
		for j := 0; j < i; j++ {
			if subtle.ConstantTimeCompare(principal.tokenDigest[:], principals[j].tokenDigest[:]) == 1 {
				return nil, errors.New("credential token values must be unique")
			}
		}
	}
	if !hasEvaluator || !hasAdmin {
		return nil, errors.New("credential configuration requires evaluator and administrator roles")
	}
	return &credentialSet{principals: principals}, nil
}

func loadTokenCredentialPath(path, label string) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	data, err := readTrustedCredentialFile(path, label, maxCredentialTokenSize, 0o077)
	if err != nil {
		return empty, err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 || strings.ContainsAny(token, " \t\r\n") {
		return empty, fmt.Errorf("%s must be at least 32 bytes without whitespace", label)
	}
	return sha256.Sum256([]byte(token)), nil
}

type credentialPathIdentity struct {
	path string
	info os.FileInfo
}

func readTrustedCredentialFile(path, label string, limit int64, forbiddenFileMode os.FileMode) ([]byte, error) {
	before, err := inspectTrustedCredentialPath(path, forbiddenFileMode, os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("inspect %s: %w", label, err)
	}
	data, err := readRegularPolicyFile(path, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", label, err)
	}
	after, err := inspectTrustedCredentialPath(path, forbiddenFileMode, os.Geteuid())
	if err != nil {
		return nil, fmt.Errorf("reinspect %s: %w", label, err)
	}
	if len(before) != len(after) {
		return nil, fmt.Errorf("%s path changed while reading", label)
	}
	for i := range before {
		if before[i].path != after[i].path || !os.SameFile(before[i].info, after[i].info) {
			return nil, fmt.Errorf("%s path changed while reading", label)
		}
	}
	return data, nil
}

func inspectTrustedCredentialPath(path string, forbiddenFileMode os.FileMode, effectiveUID int) ([]credentialPathIdentity, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("path must be absolute and clean")
	}
	identities := make([]credentialPathIdentity, 0, 8)
	for cursor, file := path, true; ; cursor, file = filepath.Dir(cursor), false {
		info, err := os.Lstat(cursor) // #nosec G703 -- explicit operator path component is inspected without following links
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s must not be a symbolic link", cursor)
		}
		owner, ok := credentialOwnerUID(info)
		if !ok || (owner != "0" && owner != strconv.Itoa(effectiveUID)) {
			return nil, fmt.Errorf("%s must be owned by root or effective uid %d", cursor, effectiveUID)
		}
		if file {
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("%s must be a regular file", cursor)
			}
			if info.Mode().Perm()&forbiddenFileMode != 0 {
				return nil, fmt.Errorf("%s has unsafe permissions", cursor)
			}
			if !credentialFileHasSingleLink(info) {
				return nil, fmt.Errorf("%s must have exactly one hard link", cursor)
			}
		} else {
			if !info.IsDir() {
				return nil, fmt.Errorf("%s must be a directory", cursor)
			}
			if info.Mode().Perm()&0o022 != 0 {
				return nil, fmt.Errorf("%s must not be group- or other-writable", cursor)
			}
		}
		identities = append(identities, credentialPathIdentity{path: cursor, info: info})
		parent := filepath.Dir(cursor)
		if parent == cursor {
			break
		}
	}
	return identities, nil
}

func credentialStatField(info os.FileInfo, name string) (string, bool) {
	value := reflect.ValueOf(info.Sys())
	if !value.IsValid() {
		return "", false
	}
	if value.Kind() == reflect.Pointer {
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return "", false
	}
	field := value.FieldByName(name)
	if !field.IsValid() {
		return "", false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(field.Uint(), 10), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if field.Int() < 0 {
			return "", false
		}
		return strconv.FormatInt(field.Int(), 10), true
	default:
		return "", false
	}
}

func credentialOwnerUID(info os.FileInfo) (string, bool) {
	return credentialStatField(info, "Uid")
}

func credentialFileHasSingleLink(info os.FileInfo) bool {
	links, ok := credentialStatField(info, "Nlink")
	return ok && links == "1"
}

func roleMap(roles ...gatewayRole) map[gatewayRole]struct{} {
	result := make(map[gatewayRole]struct{}, len(roles))
	for _, role := range roles {
		result[role] = struct{}{}
	}
	return result
}

func (credentials *credentialSet) authenticate(r *http.Request) *credentialPrincipal {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return nil
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	if len(token) < 32 || len(token) > maxCredentialTokenSize || strings.ContainsAny(token, " \t\r\n") {
		return nil
	}
	digest := sha256.Sum256([]byte(token))
	match := -1
	for i := range credentials.principals {
		if subtle.ConstantTimeCompare(digest[:], credentials.principals[i].tokenDigest[:]) == 1 {
			match = i
		}
	}
	if match < 0 {
		return nil
	}
	return &credentials.principals[match]
}

func authenticatedCredentialHandler(next http.Handler, credentials *credentialSet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		principal := credentials.authenticate(r)
		if principal == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), credentialContextKey{}, principal)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requireRole(w http.ResponseWriter, r *http.Request, role gatewayRole) bool {
	principal, _ := r.Context().Value(credentialContextKey{}).(*credentialPrincipal)
	if principal == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	if _, allowed := principal.roles[role]; !allowed {
		http.Error(w, "forbidden", http.StatusForbidden)
		return false
	}
	return true
}

func authenticatedIdentity(r *http.Request) string {
	principal, _ := r.Context().Value(credentialContextKey{}).(*credentialPrincipal)
	if principal == nil {
		return ""
	}
	return principal.identity
}

func requestAuditContext(r *http.Request, policyDigest string) AuditContext {
	return AuditContext{Identity: authenticatedIdentity(r), PolicyDigest: policyDigest}
}
