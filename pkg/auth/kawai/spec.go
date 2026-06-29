package kawai

import "github.com/getkin/kin-openapi/openapi3"

// InjectCustomAuth makes every authenticated operation in the spec also accept
// the customAuth security scheme, so edge-trusted requests are routed to the
// CustomAuthenticator. It is applied at spec-load time (in registerSpec) when
// edge auth is enabled — avoiding any change to / regeneration of the OpenAPI
// contract. Operations that require neither bearerAuth nor cookieAuth (public /
// no-auth routes) are left untouched.
func InjectCustomAuth(spec *openapi3.T) {
	if spec == nil {
		return
	}

	// Register the scheme so the resulting spec stays valid.
	if spec.Components == nil {
		spec.Components = &openapi3.Components{}
	}
	if spec.Components.SecuritySchemes == nil {
		spec.Components.SecuritySchemes = openapi3.SecuritySchemes{}
	}
	if _, ok := spec.Components.SecuritySchemes["customAuth"]; !ok {
		spec.Components.SecuritySchemes["customAuth"] = &openapi3.SecuritySchemeRef{
			Value: &openapi3.SecurityScheme{Type: "apiKey", In: "header", Name: "X-User-Id"},
		}
	}

	if spec.Paths == nil {
		return
	}

	custom := openapi3.NewSecurityRequirement().Authenticate("customAuth")

	for _, pathItem := range spec.Paths.Map() {
		for _, op := range pathItem.Operations() {
			// Effective security = the operation's own, or the global default.
			eff := op.Security
			if eff == nil || len(*eff) == 0 {
				eff = &spec.Security
			}

			if !hasScheme(eff, "bearerAuth") && !hasScheme(eff, "cookieAuth") {
				continue
			}
			if hasScheme(eff, "customAuth") {
				continue
			}

			// Set explicitly on the operation (copy of effective + customAuth) so
			// NewMiddlewareHandler uses it instead of falling back to the global.
			merged := make(openapi3.SecurityRequirements, 0, len(*eff)+1)
			merged = append(merged, *eff...)
			merged = append(merged, custom)
			op.Security = &merged
		}
	}
}

func hasScheme(reqs *openapi3.SecurityRequirements, name string) bool {
	if reqs == nil {
		return false
	}
	for _, r := range *reqs {
		if _, ok := r[name]; ok {
			return true
		}
	}
	return false
}
