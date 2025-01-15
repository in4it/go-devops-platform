package rest

import (
	"io/fs"
	"net/http"
)

func (c *Context) getRouter(assets fs.FS, indexHtml []byte) *http.ServeMux {
	mux := http.NewServeMux()

	// static files
	mux.Handle("/assets/{filename}", http.FileServer(http.FS(assets)))
	mux.Handle("/index.html", returnIndexOrNotFound(indexHtml))
	mux.Handle("/favicon.ico", http.FileServer(http.FS(assets)))
	mux.Handle("/robots.txt", returnRobotsTxt())

	// saml authentication
	mux.Handle("/saml/", c.SAML.Client.GetRouter())

	// endpoints with no authentication
	mux.Handle("/api/context", http.HandlerFunc(c.contextHandler))
	mux.Handle("/api/auth", http.HandlerFunc(c.authHandler))
	mux.Handle("/api/authmethods", http.HandlerFunc(c.authMethods))
	mux.Handle("/api/authmethods/{method}/{id}", http.HandlerFunc(c.authMethodsByID))
	mux.Handle("/api/authmethods/{id}", http.HandlerFunc(c.authMethodsByID))
	mux.Handle("/api/upgrade", http.HandlerFunc(c.upgrade))
	mux.Handle("/", returnIndexOrNotFound(indexHtml))

	// endpoints for apps
	for appName, app := range c.Apps.Clients {
		mux.Handle("/api/"+appName+"/", app.GetRouter())
	}

	// scim
	mux.Handle("/api/scim/", c.isSCIMEnabled(c.SCIM.Client.GetRouter()))

	// endpoints with authentication
	mux.Handle("/api/userinfo", c.authMiddleware(c.injectUserMiddleware(http.HandlerFunc(c.userinfoHandler))))
	mux.Handle("/api/profile/password", c.authMiddleware(c.injectUserMiddleware(http.HandlerFunc(c.profilePasswordHandler))))
	mux.Handle("/api/profile/factors", c.authMiddleware(c.injectUserMiddleware(http.HandlerFunc(c.profileFactorsHandler))))
	mux.Handle("/api/profile/factors/{name}", c.authMiddleware(c.injectUserMiddleware(http.HandlerFunc(c.profileFactorsHandler))))

	// endpoints with authentication, with admin role
	mux.Handle("/api/license", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.licenseHandler)))))
	mux.Handle("/api/license/{action}", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.licenseHandler)))))
	mux.Handle("/api/oidc", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.oidcProviderHandler)))))
	mux.Handle("/api/oidc-renew-tokens", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.oidcRenewTokensHandler)))))
	mux.Handle("/api/oidc/{id}", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.oidcProviderElementHandler)))))
	mux.Handle("/api/setup/general", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.setupHandler)))))
	mux.Handle("/api/scim-setup", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.scimSetupHandler)))))
	mux.Handle("/api/saml-setup", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.samlSetupHandler)))))
	mux.Handle("/api/saml-setup/{id}", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.samlSetupElementHandler)))))
	mux.Handle("/api/users", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.usersHandler)))))
	mux.Handle("/api/user/{id}", c.authMiddleware(c.injectUserMiddleware(c.isAdminMiddleware(http.HandlerFunc(c.userHandler)))))

	return mux
}
