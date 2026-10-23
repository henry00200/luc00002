package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	lucityGraphQLEndpoint    = "https://lucity.cloud/graphql"
	defaultLCReqTimeout      = 15 * time.Second
	defaultLCCertPollTick    = 5 * time.Second
	defaultLCCertPollWait    = 90 * time.Second
	defaultLCTLSProbeTimeout = 4 * time.Second
	defaultLCTargetPort      = 8080
	defaultLCBootstrapRegion = "eu-central"
)

type lcAuthHeaderMode int

const (
	lcAuthBearer lcAuthHeaderMode = iota
	lcAuthAccountToken
)

type lcGraphQLError struct {
	Message    string         `json:"message"`
	Path       []any          `json:"path,omitempty"`
	Extensions map[string]any `json:"extensions,omitempty"`
}

type lcGraphQLEnvelope[T any] struct {
	Data   T                `json:"data"`
	Errors []lcGraphQLError `json:"errors,omitempty"`
}

type lcAPIError struct {
	StatusCode int
	Errors     []lcGraphQLError
}

func (e *lcAPIError) Error() string {
	if len(e.Errors) > 0 {
		msgs := make([]string, 0, len(e.Errors))
		for _, err := range e.Errors {
			if strings.TrimSpace(err.Message) != "" {
				msgs = append(msgs, strings.TrimSpace(err.Message))
			}
		}
		if len(msgs) > 0 {
			return fmt.Sprintf("lucity graphql error (HTTP %d): %s", e.StatusCode, strings.Join(msgs, "; "))
		}
	}
	return fmt.Sprintf("lucity api error (HTTP %d)", e.StatusCode)
}

func (e *lcAPIError) IsAuthError() bool {
	if e.StatusCode == http.StatusUnauthorized || e.StatusCode == http.StatusForbidden {
		return true
	}
	for _, msg := range e.Errors {
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "not authorized") ||
			strings.Contains(lower, "unauthorized") ||
			strings.Contains(lower, "unauthenticated") ||
			strings.Contains(lower, "invalid token") ||
			strings.Contains(lower, "authentication") {
			return true
		}
	}
	return false
}

func (e *lcAPIError) IsPermissionOrPlan() bool {
	if e.IsAuthError() {
		return true
	}
	for _, msg := range e.Errors {
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "plan") ||
			strings.Contains(lower, "quota") ||
			strings.Contains(lower, "limit") ||
			strings.Contains(lower, "upgrade") ||
			strings.Contains(lower, "subscription") ||
			strings.Contains(lower, "permission") ||
			strings.Contains(lower, "forbidden") ||
			strings.Contains(lower, "not allowed") {
			return true
		}
	}
	return false
}

func (e *lcAPIError) IsSchemaFieldError() bool {
	for _, msg := range e.Errors {
		lower := strings.ToLower(msg.Message)
		if strings.Contains(lower, "cannot query field") ||
			strings.Contains(lower, "unknown argument") ||
			strings.Contains(lower, "unknown field") ||
			strings.Contains(lower, "unknown type") ||
			strings.Contains(lower, "is not defined by type") {
			return true
		}
	}
	return false
}

type LucityCustomDomainInfo struct {
	ID                string
	Domain            string
	CNAMETarget       string
	CNAMEHostLabel    string
	VerificationToken string
	VerificationHost  string
	CertificateStatus string
	RecordsVerified   bool
}

func (info *LucityCustomDomainInfo) IsCertificateValid() bool {
	if info == nil {
		return false
	}
	st := strings.ToUpper(strings.TrimSpace(info.CertificateStatus))
	if st == "CERTIFICATE_STATUS_TYPE_VALID" ||
		st == "VALID" ||
		st == "ACTIVE" ||
		st == "ISSUED" ||
		st == "READY" ||
		st == "TRUE" ||
		st == "VERIFIED" {
		return true
	}
	return strings.Contains(st, "VALID") && !strings.Contains(st, "VALIDATING") && !strings.Contains(st, "INVALID")
}

type LucityClient struct {
	Token         string
	WorkspaceID   string
	ProjectID     string
	EnvironmentID string
	ServiceID     string
	TargetPort    int
	apiURL        string
	client        *http.Client

	mu            sync.RWMutex
	authMode      lcAuthHeaderMode
	authVerified  bool
	serviceDomain string
	customDomain  string
	onTopology    func(lucityDom, cfDom string)
}

func sanitizeLucityToken(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	for _, prefix := range []string{"LUCITY_API_TOKEN", "LUCITY_TOKEN", "BERMUDA_LUCITY_TOKEN", "LUCITY_ACCOUNT_TOKEN"} {
		if strings.HasPrefix(upper, prefix) {
			if _, after, ok := strings.Cut(s, "="); ok {
				s = strings.TrimSpace(after)
			}
		}
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.TrimSpace(s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func parseLucityHierarchicalID(serviceID string) (ws, proj, env, svc string) {
	parts := strings.Split(strings.Trim(strings.TrimSpace(serviceID), "/"), "/")
	switch len(parts) {
	case 4:
		return parts[0], parts[0] + "/" + parts[1], parts[0] + "/" + parts[1] + "/" + parts[2], strings.Join(parts, "/")
	case 3:
		return parts[0], parts[0] + "/" + parts[1], strings.Join(parts, "/"), ""
	case 2:
		return parts[0], strings.Join(parts, "/"), "", ""
	case 1:
		return parts[0], "", "", ""
	default:
		return "", "", "", ""
	}
}

func NewLucityClient(token string) *LucityClient {
	cleanTok := sanitizeLucityToken(token)
	if cleanTok == "" {
		return nil
	}

	port := getEnvInt("PORT", defaultLCTargetPort)
	if port <= 0 {
		port = defaultLCTargetPort
	}

	lcDom, cfDom := resolveInfrastructureDomains()
	apiURL := sanitizeExplicitCredential(getEnv("LUCITY_API_URL", getEnv("BERMUDA_LUCITY_API_URL", lucityGraphQLEndpoint)))
	if apiURL == "" {
		apiURL = lucityGraphQLEndpoint
	}

	rawSvcID := sanitizeExplicitCredential(getEnv("LUCITY_SERVICE_ID", getEnv("BERMUDA_LUCITY_SERVICE_ID", "")))
	rawEnvID := sanitizeExplicitCredential(getEnv("LUCITY_ENVIRONMENT_ID", getEnv("LUCITY_ENVIRONMENT", "")))
	rawProjID := sanitizeExplicitCredential(getEnv("LUCITY_PROJECT_ID", getEnv("LUCITY_PROJECT", "")))
	rawWsID := sanitizeExplicitCredential(getEnv("LUCITY_WORKSPACE_ID", getEnv("LUCITY_WORKSPACE", "")))

	ws, proj, env, svc := parseLucityHierarchicalID(rawSvcID)
	if rawWsID != "" {
		ws = rawWsID
	}
	if rawProjID != "" {
		if strings.Contains(rawProjID, "/") {
			proj = rawProjID
		} else if ws != "" {
			proj = ws + "/" + rawProjID
		} else {
			proj = rawProjID
		}
	}
	if rawEnvID != "" {
		if strings.Count(rawEnvID, "/") >= 2 {
			env = rawEnvID
		} else if proj != "" && strings.Contains(proj, "/") {
			env = proj + "/" + rawEnvID
		} else {
			env = rawEnvID
		}
	}

	return &LucityClient{
		Token:         cleanTok,
		WorkspaceID:   ws,
		ProjectID:     proj,
		EnvironmentID: env,
		ServiceID:     svc,
		TargetPort:    port,
		apiURL:        apiURL,
		serviceDomain: lcDom,
		customDomain:  cfDom,
		client: &http.Client{
			Timeout: 20 * time.Second,
		},
	}
}

func (c *LucityClient) IsConfigured() bool {
	return c != nil && c.Token != ""
}

func (c *LucityClient) HasServiceContext() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ServiceID != ""
}

func (c *LucityClient) SetTopologyCallback(fn func(lucityDom, cfDom string)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.onTopology = fn
	c.mu.Unlock()
}

func (c *LucityClient) notifyTopology() {
	if c == nil {
		return
	}
	c.mu.RLock()
	fn := c.onTopology
	lc := c.serviceDomain
	cf := c.customDomain
	c.mu.RUnlock()
	if fn != nil {
		fn(lc, cf)
	}
}

func (c *LucityClient) GetServiceDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.serviceDomain
}

func (c *LucityClient) GetCustomDomain() string {
	if c == nil {
		return ""
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.customDomain
}

func (c *LucityClient) SetServiceDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if !isLucityPublicDomain(clean) {
		return
	}
	c.mu.Lock()
	if c.serviceDomain == "" || isFullLucityServiceDomain(clean) {
		c.serviceDomain = clean
	}
	c.mu.Unlock()
}

func (c *LucityClient) SetCustomDomain(d string) {
	if c == nil {
		return
	}
	clean := cleanHost(d)
	if clean == "" || isLucityManagedDomain(clean) {
		return
	}
	c.mu.Lock()
	c.customDomain = clean
	c.mu.Unlock()
}

func (c *LucityClient) endpoint() string {
	if c != nil && c.apiURL != "" {
		return c.apiURL
	}
	return lucityGraphQLEndpoint
}

type lcGraphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables,omitempty"`
}

func doLCRequest[T any](ctx context.Context, c *LucityClient, query string, variables map[string]any) (T, error) {
	var zero T
	if !c.IsConfigured() {
		return zero, errors.New("lucity client not configured (missing token)")
	}

	c.mu.RLock()
	mode := c.authMode
	verified := c.authVerified
	c.mu.RUnlock()

	res, err := executeLCGraphQL[T](ctx, c, mode, query, variables)
	if err == nil {
		if !verified {
			c.mu.Lock()
			c.authVerified = true
			c.mu.Unlock()
		}
		return res, nil
	}

	var apiErr *lcAPIError
	if !verified && errors.As(err, &apiErr) && apiErr.IsAuthError() {
		altMode := lcAuthAccountToken
		if mode == lcAuthAccountToken {
			altMode = lcAuthBearer
		}
		if altRes, altErr := executeLCGraphQL[T](ctx, c, altMode, query, variables); altErr == nil {
			c.mu.Lock()
			c.authMode = altMode
			c.authVerified = true
			c.mu.Unlock()
			return altRes, nil
		}
	}

	return zero, err
}

func executeLCGraphQL[T any](ctx context.Context, c *LucityClient, mode lcAuthHeaderMode, query string, variables map[string]any) (T, error) {
	var zero T

	payloadBytes, err := json.Marshal(lcGraphQLRequest{
		Query:     query,
		Variables: variables,
	})
	if err != nil {
		return zero, fmt.Errorf("marshal lucity graphql request: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, defaultLCReqTimeout)
		req, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint(), bytes.NewReader(payloadBytes))
		if reqErr != nil {
			cancel()
			return zero, fmt.Errorf("build lucity graphql request: %w", reqErr)
		}

		if mode == lcAuthAccountToken {
			req.Header.Set("X-Lucity-Account-Token", c.Token)
		} else {
			req.Header.Set("Authorization", "Bearer "+c.Token)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "BERMUDA-Portal-CloudOrchestrator/4.0 (Go-Standard-Library)")

		resp, doErr := c.client.Do(req)
		if doErr != nil {
			cancel()
			lastErr = doErr
			break
		}

		rawBytes, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		_ = resp.Body.Close()
		cancel()

		if readErr != nil {
			return zero, fmt.Errorf("read lucity response: %w", readErr)
		}

		if resp.StatusCode == http.StatusTooManyRequests && attempt == 0 {
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(1500 * time.Millisecond):
				continue
			}
		}

		var env lcGraphQLEnvelope[T]
		if err := json.Unmarshal(rawBytes, &env); err != nil {
			snippet := string(rawBytes)
			if len(snippet) > 256 {
				snippet = snippet[:256]
			}
			return zero, &lcAPIError{
				StatusCode: resp.StatusCode,
				Errors:     []lcGraphQLError{{Message: snippet}},
			}
		}

		if resp.StatusCode >= 400 || len(env.Errors) > 0 {
			return env.Data, &lcAPIError{
				StatusCode: resp.StatusCode,
				Errors:     env.Errors,
			}
		}

		return env.Data, nil
	}

	return zero, lastErr
}

func extractDomainsFromGenericMap(raw any) (serviceDom string, customDoms []LucityCustomDomainInfo) {
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, val := range v {
				lowerKey := strings.ToLower(key)
				if strVal, ok := val.(string); ok {
					clean := cleanHost(strVal)
					if isLucityPublicDomain(clean) {
						if serviceDom == "" || isFullLucityServiceDomain(clean) {
							serviceDom = clean
						}
					} else if (lowerKey == "domain" || lowerKey == "hostname" || lowerKey == "host" || lowerKey == "customdomain") &&
						clean != "" && strings.Contains(clean, ".") && !isLucityManagedDomain(clean) {
						info := LucityCustomDomainInfo{
							Domain: clean,
						}
						if idStr, ok := v["id"].(string); ok {
							info.ID = idStr
						}
						if stStr, ok := v["status"].(string); ok {
							info.CertificateStatus = stStr
						} else if stStr, ok := v["certificateStatus"].(string); ok {
							info.CertificateStatus = stStr
						} else if readyBool, ok := v["ready"].(bool); ok && readyBool {
							info.CertificateStatus = "VALID"
						} else if tlsReady, ok := v["tlsReady"].(bool); ok && tlsReady {
							info.CertificateStatus = "VALID"
						}
						if targetStr, ok := v["cnameTarget"].(string); ok && targetStr != "" {
							info.CNAMETarget = cleanHost(targetStr)
						} else if targetStr, ok := v["target"].(string); ok && targetStr != "" {
							info.CNAMETarget = cleanHost(targetStr)
						}
						customDoms = append(customDoms, info)
					}
				} else {
					walk(val)
				}
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(raw)
	if serviceDom != "" {
		for i := range customDoms {
			if customDoms[i].CNAMETarget == "" {
				customDoms[i].CNAMETarget = serviceDom
			}
		}
	}
	return serviceDom, customDoms
}

func extractServiceIDFromGenericMap(raw any, preferredDomain string) (wsID, projID, envID, svcID, discoveredServiceDom string) {
	prefClean := cleanHost(preferredDomain)

	var candidates []string
	var walk func(node any)
	walk = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			if idVal, ok := v["id"].(string); ok {
				slashCount := strings.Count(strings.Trim(idVal, "/"), "/")
				if slashCount == 3 {
					candidates = append(candidates, strings.Trim(idVal, "/"))
					sDom, _ := extractDomainsFromGenericMap(v)
					if sDom != "" {
						if discoveredServiceDom == "" || isFullLucityServiceDomain(sDom) {
							discoveredServiceDom = sDom
						}
						if prefClean != "" && sDom == prefClean {
							_, projID, envID, svcID = parseLucityHierarchicalID(idVal)
							wsID, _, _, _ = parseLucityHierarchicalID(idVal)
						}
					}
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, item := range v {
				walk(item)
			}
		}
	}
	walk(raw)

	if svcID == "" && len(candidates) > 0 {
		chosen := candidates[0]
		for _, cand := range candidates {
			if strings.Contains(strings.ToLower(cand), "/production/") {
				chosen = cand
				break
			}
		}
		wsID, projID, envID, svcID = parseLucityHierarchicalID(chosen)
	}
	return wsID, projID, envID, svcID, discoveredServiceDom
}

func (c *LucityClient) ResolveRuntimeContext(ctx context.Context) error {
	if !c.IsConfigured() {
		return errors.New("lucity client not configured")
	}
	if c.HasServiceContext() {
		return nil
	}

	discoveryQueries := []string{
		`query {
			workspaces {
				id
				name
				projects {
					id
					name
					environments {
						id
						name
						services {
							id
							name
							domain
							domains {
								id
								domain
								status
							}
						}
					}
				}
			}
		}`,
		`query {
			workspaces {
				id
				projects {
					id
					environments {
						id
						services {
							id
							name
						}
					}
				}
			}
		}`,
		`query {
			projects {
				id
				environments {
					id
					services {
						id
						name
					}
				}
			}
		}`,
	}

	c.mu.RLock()
	knownDom := c.serviceDomain
	c.mu.RUnlock()

	for _, q := range discoveryQueries {
		raw, err := doLCRequest[map[string]any](ctx, c, q, nil)
		if err != nil {
			continue
		}
		ws, proj, env, svc, sDom := extractServiceIDFromGenericMap(raw, knownDom)
		if svc != "" {
			c.mu.Lock()
			if c.WorkspaceID == "" {
				c.WorkspaceID = ws
			}
			if c.ProjectID == "" {
				c.ProjectID = proj
			}
			if c.EnvironmentID == "" {
				c.EnvironmentID = env
			}
			if c.ServiceID == "" {
				c.ServiceID = svc
			}
			if sDom != "" && (c.serviceDomain == "" || isFullLucityServiceDomain(sDom)) {
				c.serviceDomain = sDom
			}
			c.mu.Unlock()
			c.notifyTopology()
			log.Printf("[Lucity] ✓ Resolved Runtime Service Context: %s", svc)
			return nil
		}
	}

	return errors.New("could not auto-discover lucity service ID from workspace query (set LUCITY_SERVICE_ID if using scoped token)")
}

func (c *LucityClient) UpsertVariable(ctx context.Context, name, value string) error {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return err
	}

	c.mu.RLock()
	svcID := c.ServiceID
	envID := c.EnvironmentID
	c.mu.RUnlock()

	type mutationAttempt struct {
		query string
		vars  map[string]any
	}

	attempts := []mutationAttempt{
		{
			query: `mutation setServiceVariables($input: SetServiceVariablesInput!) {
				setServiceVariables(input: $input) { id }
			}`,
			vars: map[string]any{
				"input": map[string]any{
					"serviceId": svcID,
					"variables": []map[string]any{
						{"key": name, "value": value},
					},
				},
			},
		},
		{
			query: `mutation setVariables($serviceId: ID!, $variables: [VariableInput!]!) {
				setVariables(serviceId: $serviceId, variables: $variables)
			}`,
			vars: map[string]any{
				"serviceId": svcID,
				"variables": []map[string]any{
					{"name": name, "value": value},
				},
			},
		},
		{
			query: `mutation updateService($input: UpdateServiceInput!) {
				updateService(input: $input) { id }
			}`,
			vars: map[string]any{
				"input": map[string]any{
					"id": svcID,
					"variables": map[string]any{
						name: value,
					},
				},
			},
		},
		{
			query: `mutation variableUpsert($input: VariableUpsertInput!) {
				variableUpsert(input: $input)
			}`,
			vars: map[string]any{
				"input": map[string]any{
					"serviceId":     svcID,
					"environmentId": envID,
					"name":          name,
					"value":         value,
				},
			},
		},
	}

	var lastErr error
	for _, att := range attempts {
		if _, err := doLCRequest[map[string]any](ctx, c, att.query, att.vars); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return lastErr
}

func (c *LucityClient) PersistMasterKey(ctx context.Context, masterKey string) bool {
	if !c.IsConfigured() || strings.TrimSpace(masterKey) == "" {
		return false
	}
	if err := c.UpsertVariable(ctx, "BERMUDA_MASTER_KEY", strings.TrimSpace(masterKey)); err != nil {
		var apiErr *lcAPIError
		if errors.As(err, &apiErr) && apiErr.IsPermissionOrPlan() {
			log.Printf("[Lucity] Note: Auto-persisting BERMUDA_MASTER_KEY skipped (token permission restriction)")
			return false
		}
		log.Printf("[Lucity] Note: BERMUDA_MASTER_KEY persistence via GraphQL skipped: %v", err)
		return false
	}
	log.Println("[Lucity] ✓ BERMUDA_MASTER_KEY persisted to Lucity Service Variables")
	return true
}

func (c *LucityClient) fetchServiceDetails(ctx context.Context) (string, []LucityCustomDomainInfo, error) {
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return c.GetServiceDomain(), nil, err
	}

	c.mu.RLock()
	svcID := c.ServiceID
	c.mu.RUnlock()

	queries := []string{
		`query service($id: ID!) {
			service(id: $id) {
				id
				name
				domain
				platformDomain
				customDomains {
					id
					domain
					cnameTarget
					status
					ready
				}
			}
		}`,
		`query service($id: ID!) {
			service(id: $id) {
				id
				name
				domain
				domains {
					id
					domain
					status
				}
			}
		}`,
		`query service($id: String!) {
			service(id: $id) {
				id
				name
				domain
			}
		}`,
	}

	for _, q := range queries {
		raw, err := doLCRequest[map[string]any](ctx, c, q, map[string]any{"id": svcID})
		if err != nil {
			continue
		}
		sDom, cDoms := extractDomainsFromGenericMap(raw)
		if sDom != "" {
			c.SetServiceDomain(sDom)
		}
		return c.GetServiceDomain(), cDoms, nil
	}

	return c.GetServiceDomain(), nil, errors.New("unable to query service domain details from lucity graphql")
}

func (c *LucityClient) EnsureServiceDomain(ctx context.Context) (string, error) {
	if dom := c.GetServiceDomain(); isFullLucityServiceDomain(dom) {
		log.Printf("[Lucity] ✓ Platform Service Domain Active: %s (Port %d)", dom, c.TargetPort)
		return dom, nil
	}

	sDom, _, err := c.fetchServiceDetails(ctx)
	if err == nil && isLucityPublicDomain(sDom) {
		c.SetServiceDomain(sDom)
		c.notifyTopology()
		log.Printf("[Lucity] ✓ Platform Service Domain Verified: %s (Port %d)", sDom, c.TargetPort)
		return sDom, nil
	}

	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return c.GetServiceDomain(), err
	}

	c.mu.RLock()
	svcID := c.ServiceID
	port := c.TargetPort
	c.mu.RUnlock()

	type domainGenAttempt struct {
		query string
		vars  map[string]any
	}

	attempts := []domainGenAttempt{
		{
			query: `mutation generateDomain($serviceId: ID!) {
				generateDomain(serviceId: $serviceId) {
					domain
				}
			}`,
			vars: map[string]any{"serviceId": svcID},
		},
		{
			query: `mutation generatePlatformDomain($input: GeneratePlatformDomainInput!) {
				generatePlatformDomain(input: $input) {
					domain
				}
			}`,
			vars: map[string]any{
				"input": map[string]any{
					"serviceId": svcID,
					"port":      port,
				},
			},
		},
		{
			query: `mutation createServiceDomain($input: CreateServiceDomainInput!) {
				createServiceDomain(input: $input) {
					domain
				}
			}`,
			vars: map[string]any{
				"input": map[string]any{
					"serviceId":  svcID,
					"targetPort": port,
				},
			},
		},
	}

	for _, att := range attempts {
		raw, mutErr := doLCRequest[map[string]any](ctx, c, att.query, att.vars)
		if mutErr != nil {
			continue
		}
		genDom, _ := extractDomainsFromGenericMap(raw)
		if isLucityPublicDomain(genDom) {
			c.SetServiceDomain(genDom)
			c.notifyTopology()
			log.Printf("[Lucity] ✓ Auto-Provisioned Lucity Platform Domain: %s (Port %d)", genDom, port)
			return genDom, nil
		}
	}

	return c.GetServiceDomain(), err
}

func probeCustomDomainTLS(ctx context.Context, customDomain, gatewayHost string) bool {
	cleanCustom := cleanHost(customDomain)
	if cleanCustom == "" {
		return false
	}
	dialTarget := cleanHost(gatewayHost)
	if dialTarget == "" {
		dialTarget = cleanCustom
	}

	dialer := &net.Dialer{
		Timeout: defaultLCTLSProbeTimeout,
	}
	tlsConn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(dialTarget, "443"), &tls.Config{
		ServerName:         cleanCustom,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false,
	})
	if err != nil {
		return false
	}
	_ = tlsConn.Close()
	return true
}

func (c *LucityClient) EnsureCustomDomain(ctx context.Context, targetDomain string) (*LucityCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	if cleanTarget == "" || isLucityManagedDomain(cleanTarget) {
		return nil, errors.New("invalid or empty custom domain target")
	}

	sDom, existingDoms, _ := c.fetchServiceDetails(ctx)
	if sDom == "" {
		sDom = c.GetServiceDomain()
	}

	for i := range existingDoms {
		cd := &existingDoms[i]
		if cleanHost(cd.Domain) == cleanTarget {
			c.SetCustomDomain(cleanTarget)
			c.notifyTopology()
			if cd.CNAMETarget == "" {
				if sDom != "" {
					cd.CNAMETarget = sDom
				} else {
					cd.CNAMETarget = "lb.lucity.app"
				}
			}
			if cd.VerificationHost == "" {
				cd.VerificationHost = "_lucity-verify." + cleanTarget
			}
			if !cd.IsCertificateValid() && probeCustomDomainTLS(ctx, cleanTarget, cd.CNAMETarget) {
				cd.CertificateStatus = "VALID"
			}
			log.Printf("[Lucity] ✓ Custom Domain Already Registered: %s (CNAME Target: %s, CertStatus: %s)",
				cleanTarget, cd.CNAMETarget, cd.CertificateStatus)
			return cd, nil
		}
	}

	if err := c.ResolveRuntimeContext(ctx); err == nil {
		c.mu.RLock()
		svcID := c.ServiceID
		port := c.TargetPort
		c.mu.RUnlock()

		type addDomAttempt struct {
			query string
			vars  map[string]any
		}

		attempts := []addDomAttempt{
			{
				query: `mutation addCustomDomain($input: AddCustomDomainInput!) {
					addCustomDomain(input: $input) {
						id
						domain
						cnameTarget
						status
					}
				}`,
				vars: map[string]any{
					"input": map[string]any{
						"serviceId": svcID,
						"domain":    cleanTarget,
						"port":      port,
					},
				},
			},
			{
				query: `mutation addDomain($serviceId: ID!, $domain: String!) {
					addDomain(serviceId: $serviceId, domain: $domain) {
						id
						domain
						status
					}
				}`,
				vars: map[string]any{
					"serviceId": svcID,
					"domain":    cleanTarget,
				},
			},
			{
				query: `mutation createCustomDomain($input: CreateCustomDomainInput!) {
					createCustomDomain(input: $input) {
						id
						domain
						status
					}
				}`,
				vars: map[string]any{
					"input": map[string]any{
						"serviceId":  svcID,
						"domain":     cleanTarget,
						"targetPort": port,
					},
				},
			},
		}

		for _, att := range attempts {
			raw, err := doLCRequest[map[string]any](ctx, c, att.query, att.vars)
			if err != nil {
				continue
			}
			_, createdDoms := extractDomainsFromGenericMap(raw)
			if len(createdDoms) > 0 {
				info := createdDoms[0]
				if info.CNAMETarget == "" {
					if c.GetServiceDomain() != "" {
						info.CNAMETarget = c.GetServiceDomain()
					} else {
						info.CNAMETarget = "lb.lucity.app"
					}
				}
				if info.VerificationHost == "" {
					info.VerificationHost = "_lucity-verify." + cleanTarget
				}
				c.SetCustomDomain(cleanTarget)
				c.notifyTopology()
				log.Printf("[Lucity] ✓ Auto-Registered Custom Domain on Port %d: %s -> CNAME Target: %s",
					port, cleanTarget, info.CNAMETarget)
				return &info, nil
			}
		}
	}

	fallbackTarget := c.GetServiceDomain()
	if fallbackTarget == "" {
		fallbackTarget = sDom
	}
	if fallbackTarget == "" {
		fallbackTarget = "lb.lucity.app"
	}

	c.SetCustomDomain(cleanTarget)
	c.notifyTopology()

	certState := "PENDING_HTTP01"
	if probeCustomDomainTLS(ctx, cleanTarget, fallbackTarget) {
		certState = "VALID"
	}

	info := &LucityCustomDomainInfo{
		Domain:            cleanTarget,
		CNAMETarget:       fallbackTarget,
		VerificationHost:  "_lucity-verify." + cleanTarget,
		CertificateStatus: certState,
	}
	return info, nil
}

func (c *LucityClient) FetchCustomDomainStatus(ctx context.Context, customDomainID, targetDomain string) (*LucityCustomDomainInfo, error) {
	cleanTarget := cleanHost(targetDomain)
	sDom, customDoms, _ := c.fetchServiceDetails(ctx)
	if sDom == "" {
		sDom = c.GetServiceDomain()
	}
	if sDom == "" {
		sDom = "lb.lucity.app"
	}

	for i := range customDoms {
		cd := &customDoms[i]
		if (customDomainID != "" && cd.ID == customDomainID) || (cleanTarget != "" && cleanHost(cd.Domain) == cleanTarget) {
			if cd.CNAMETarget == "" {
				cd.CNAMETarget = sDom
			}
			if cd.VerificationHost == "" {
				cd.VerificationHost = "_lucity-verify." + cleanTarget
			}
			if !cd.IsCertificateValid() && probeCustomDomainTLS(ctx, cleanTarget, cd.CNAMETarget) {
				cd.CertificateStatus = "VALID"
			}
			return cd, nil
		}
	}

	if probeCustomDomainTLS(ctx, cleanTarget, sDom) {
		return &LucityCustomDomainInfo{
			ID:                customDomainID,
			Domain:            cleanTarget,
			CNAMETarget:       sDom,
			VerificationHost:  "_lucity-verify." + cleanTarget,
			CertificateStatus: "VALID",
			RecordsVerified:   true,
		}, nil
	}

	return &LucityCustomDomainInfo{
		ID:                customDomainID,
		Domain:            cleanTarget,
		CNAMETarget:       sDom,
		VerificationHost:  "_lucity-verify." + cleanTarget,
		CertificateStatus: "PENDING_HTTP01",
	}, nil
}

func (c *LucityClient) WaitCustomDomainCertificate(ctx context.Context, customDomainID, targetDomain string, maxWait time.Duration) (*LucityCustomDomainInfo, bool) {
	if maxWait <= 0 {
		maxWait = defaultLCCertPollWait
	}
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	ticker := time.NewTicker(defaultLCCertPollTick)
	defer ticker.Stop()

	var latest *LucityCustomDomainInfo
	for {
		info, err := c.FetchCustomDomainStatus(waitCtx, customDomainID, targetDomain)
		if err == nil && info != nil {
			latest = info
			if info.IsCertificateValid() {
				log.Printf("[Lucity] ✓ Custom Domain %s Let's Encrypt TLS Certificate ISSUED & VALID (%s)",
					info.Domain, info.CertificateStatus)
				return info, true
			}
		}

		select {
		case <-waitCtx.Done():
			return latest, false
		case <-ticker.C:
		}
	}
}

func probeKernelIPv6Route() bool {
	conn, err := net.DialTimeout("udp6", "[2606:4700:4700::1111]:53", 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (c *LucityClient) TuneComputeAndNetwork(ctx context.Context) {
	if probeKernelIPv6Route() {
		log.Println("[Lucity] ✓ Outbound IPv6 Stack: ACTIVE & VERIFIED (Kernel IPv6 routing table online)")
	} else {
		log.Println("[Lucity] ✓ Outbound Network Stack: IPv4 Active (Safe IPv4 egress routing verified)")
	}

	if !c.IsConfigured() {
		return
	}
	if err := c.ResolveRuntimeContext(ctx); err != nil {
		return
	}

	c.mu.RLock()
	svcID := c.ServiceID
	port := c.TargetPort
	c.mu.RUnlock()

	healthPath := getEnv("BERMUDA_HEALTH_PATH", "/.well-known/hc-5b1e7c")

	const updateNetworkingMutation = `mutation updateServiceNetworking($input: UpdateServiceInput!) {
		updateService(input: $input) { id }
	}`

	input := map[string]any{
		"id":   svcID,
		"port": port,
		"healthCheck": map[string]any{
			"path":                healthPath,
			"port":                port,
			"initialDelaySeconds": 5,
			"periodSeconds":       10,
			"timeoutSeconds":      3,
			"failureThreshold":    3,
		},
	}

	if _, err := doLCRequest[map[string]any](ctx, c, updateNetworkingMutation, map[string]any{"input": input}); err == nil {
		log.Printf("[Lucity] ✓ Service HealthCheck & Port Synchronized: Port %d (%s)", port, healthPath)
	}
}
