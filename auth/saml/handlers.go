package saml

import (
	"fmt"
	"net/http"
)

func (s *saml) samlHandler(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("id")

	if providerID == "" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("saml error: no provider specified\n"))
		return
	}

	provider, err := s.getProviderByID(providerID)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("saml error: can't find provider with specified id: %s", err)))
		return
	}

	err = s.ensureSPLoaded(provider)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("saml error: invalid saml configuration: %s\n", err)))
		return
	}
	err = r.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if r.Method != "POST" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("saml error: not a POST request\n"))
		return
	}

	if r.FormValue("SAMLResponse") == "" {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("saml error: empty SAMLResponse\n"))
		return
	}

	sp, ok := s.getServiceProvider(providerID)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("saml error: can't find provider with specified id\n"))
		return
	}

	assertionInfo, err := sp.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("saml error: %s\n", err)))
		return
	}

	if assertionInfo.WarningInfo.InvalidTime {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("saml error: invalid time\n"))
		return
	}

	if assertionInfo.WarningInfo.NotInAudience {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("saml error: incorrect audience\n"))
		return
	}

	sessionID, err := s.createSessionFromAssertion(providerID, assertionInfo)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(fmt.Sprintf("saml error: %s\n", err)))
		return
	}
	w.Header().Add("Location", fmt.Sprintf("/callback/saml/%s?code=%s", providerID, sessionID))
	w.WriteHeader(http.StatusFound)
}
