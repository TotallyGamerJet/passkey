package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/mail"
	"os"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn  *webauthn.WebAuthn
	datastore *InMem
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passkey</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://unpkg.com/htmx.org@2.0.3"></script>
</head>
<body>
{{ template "form" . }}
<script src="/src/index.es5.umd.min.js"></script>
</body>
</html>

{{ define "form" }}
<div class="relative flex min-h-screen flex-col justify-center overflow-hidden bg-gray-50 py-6 sm:py-12">
  <img src="/img/beams.jpg" alt="" class="absolute left-1/2 top-1/2 max-w-none -translate-x-1/2 -translate-y-1/2" width="1308" />
  <div class="absolute inset-0 bg-[url(/img/grid.svg)] bg-center [mask-image:linear-gradient(180deg,white,rgba(255,255,255,0))]"></div>
  <div class="relative bg-white px-6 pb-8 pt-10 shadow-xl ring-1 ring-gray-900/5 sm:mx-auto sm:max-w-lg sm:rounded-lg sm:px-10">
    <div class="mx-auto max-w-md">
      <form id="login" class="group mx-auto max-w-sm">
        <div class="mb-5">
          <label for="email" class="mb-2 block text-sm font-medium text-gray-900 dark:text-white">Your email</label>
          <span class="peer mb-2 block text-sm font-light text-red-600">{{ . }}</span>
          <input autocomplete="email" name="email" type="email" id="email" class="block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-blue-500 peer-[&:not(:empty)]:border-red-400 dark:border-gray-600 dark:bg-gray-700 dark:text-white dark:placeholder-gray-400 dark:focus:border-blue-500 dark:focus:ring-blue-500" placeholder="name@flowbite.com" required />
        </div>
        <button id="register-button" hx-get="/register" hx-include="[name='email']" hx-swap="beforeend" hx-target="body" hx-indicator="#login" hx-disabled-elt="this, #login-button, #email" type="submit" class="w-full rounded-lg bg-blue-700 px-5 py-2.5 text-center text-sm font-medium text-white hover:bg-blue-800 focus:outline-none focus:ring-4 focus:ring-blue-300 disabled:bg-slate-300 sm:w-auto dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800">Register</button>
        <button id="login-button" hx-get="/login" hx-include="[name='email']" hx-swap="beforeend" hx-target="body" hx-indicator="#login" hx-disabled-elt="this, #register-button, #email" type="submit" class="w-full rounded-lg bg-blue-700 px-5 py-2.5 text-center text-sm font-medium text-white hover:bg-blue-800 focus:outline-none focus:ring-4 focus:ring-blue-300 disabled:bg-slate-300 sm:w-auto dark:bg-blue-600 dark:hover:bg-blue-700 dark:focus:ring-blue-800">Sign in</button>
      </form>
    </div>
  </div>
</div>

{{ end }}
`

var indexTemplate = template.Must(template.New("").Parse(htmlTemplate))

func main() {
	proto := "https"
	host := "localhost"
	port := ":8080"
	origin := fmt.Sprintf("%s://%s%s", proto, host, port)

	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",    // Display Name for your site
		RPID:          host,             // Generally the FQDN for your site
		RPOrigins:     []string{origin}, // The origin URLs allowed for WebAuthn
	}

	var err error
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}

	datastore = NewInMem()

	http.Handle("/src/", http.StripPrefix("/src/", http.FileServer(http.Dir("./web"))))
	http.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		_ = indexTemplate.Execute(w, nil)
	})
	http.HandleFunc("GET /register", BeginRegistration)
	http.HandleFunc("POST /register", FinishRegistration)
	http.HandleFunc("GET /login", BeginLogin)
	http.HandleFunc("POST /login", FinishLogin)
	http.Handle("GET /private", LoggedInMiddleware(http.HandlerFunc(PrivatePage)))

	slog.Info("starting server", "url", origin)
	// Generate self-signed certificates for development
	// go run $GOROOT/src/crypto/tls/generate_cert.go --host="localhost"
	if err := http.ListenAndServeTLS(port, "cert.pem", "key.pem", nil); err != nil {
		slog.Error("failed to listen and serve", "err", err.Error())
	}
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		slog.ErrorContext(r.Context(), "form parse error", "err", err.Error())
		return
	}
	email, err := mail.ParseAddress(r.FormValue("email"))
	if err != nil {
		slog.DebugContext(r.Context(), "email parse error", "err", err)
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "incorrect email format")
		return
	}
	user := datastore.GetOrCreateUser(email.Address)

	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		slog.Info("can't begin registration", "err", err)
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}

	t, err := datastore.GenSessionID()
	if err != nil {
		slog.ErrorContext(r.Context(), "can't generate session id", "err", err)
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}

	datastore.SaveSession(t, *session)

	http.SetCookie(w, &http.Cookie{
		Name:     "rid",
		Value:    t,
		Path:     "/register",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	optionsJson, err := json.Marshal(options)
	if err != nil {
		slog.ErrorContext(r.Context(), "can't marshal options", "err", err)
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}
	fmt.Fprintf(w, `
<script id="script">
	SimpleWebAuthnBrowser.startRegistration(JSON.parse('%s').publicKey)
		.then(attestationResponse => htmx.ajax('POST', '/register', {target: 'body', values: {data: btoa(JSON.stringify(attestationResponse))}}))
		.catch(htmx.ajax('GET', '/', 'body'))
		.finally(htmx.find('#script').remove());
</script>`, optionsJson)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	rid, err := r.Cookie("rid")
	if err != nil {
		slog.WarnContext(r.Context(), "can't get session id", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}
	defer http.SetCookie(w, &http.Cookie{
		Name:  "rid",
		Value: "",
	})
	if err = r.ParseForm(); err != nil {
		slog.WarnContext(r.Context(), "can't parse form", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}
	data, err := base64.StdEncoding.DecodeString(r.FormValue("data"))
	if err != nil {
		slog.ErrorContext(r.Context(), "can't decode form data", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}
	session, _ := datastore.GetSession(rid.Value) // FIXME: cover invalid session

	user := datastore.GetOrCreateUser(string(session.UserID)) // Get the user
	cred, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(data))
	if err != nil {
		slog.WarnContext(r.Context(), "can't parse body", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}

	credential, err := webAuthn.CreateCredential(user, session, cred)
	if err != nil {
		slog.WarnContext(r.Context(), "can't create credential", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}

	user.AddCredential(credential)
	datastore.SaveUser(user)
	datastore.DeleteSession(rid.Value)
	w.Header().Set("HX-Reswap", "innerHTML")
	indexTemplate.ExecuteTemplate(w, "form", "registration successful")
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		slog.WarnContext(r.Context(), "form parse error", "err", err.Error())
		return
	}
	email, err := mail.ParseAddress(r.FormValue("email"))
	if err != nil {
		slog.DebugContext(r.Context(), "email parse error", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "incorrect email format")
		return
	}

	user := datastore.GetOrCreateUser(email.Address)

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "login failed")
		return
	}

	t, err := datastore.GenSessionID()
	if err != nil {
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "login failed")
		return
	}
	datastore.SaveSession(t, *session)

	http.SetCookie(w, &http.Cookie{
		Name:     "lid",
		Value:    t,
		Path:     "/login",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	optionsJson, err := json.Marshal(options)
	if err != nil {
		slog.ErrorContext(r.Context(), "json marshal error", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "login failed")
		return
	}

	fmt.Fprintf(w, `
<script id="script">
  SimpleWebAuthnBrowser.startAuthentication(JSON.parse('%s').publicKey)
	.then(attestationResponse => htmx.ajax('POST', '/login', {target: 'body', values: {data: btoa(JSON.stringify(attestationResponse))}}))
	.catch(htmx.ajax('GET', '/', 'body'))
	.finally(htmx.find('#script').remove());
</script>`, optionsJson)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	lid, err := r.Cookie("lid")
	if err != nil {
		slog.ErrorContext(r.Context(), "missing lid cookie", "err", err.Error())
		return
	}
	defer datastore.DeleteSession(lid.Value)
	defer http.SetCookie(w, &http.Cookie{
		Name:  "lid",
		Value: "",
	})

	if err := r.ParseForm(); err != nil {
		slog.DebugContext(r.Context(), "form parse error", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "login failed")
		return
	}
	data, err := base64.StdEncoding.DecodeString(r.FormValue("data"))
	if err != nil {
		slog.DebugContext(r.Context(), "can't decode form data", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "login failed")
		return
	}
	session, _ := datastore.GetSession(lid.Value) // FIXME: cover invalid session
	user := datastore.GetOrCreateUser(string(session.UserID))

	cred, err := protocol.ParseCredentialRequestResponseBody(bytes.NewBuffer(data))
	if err != nil {
		slog.WarnContext(r.Context(), "can't parse cred request body", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "login failed")
		return
	}
	credential, err := webAuthn.ValidateLogin(user, session, cred)
	if err != nil {
		slog.DebugContext(r.Context(), "invalid login", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "login failed")
		return
	}

	if credential.Authenticator.CloneWarning {
		slog.WarnContext(r.Context(), "can't finish login: CloneWarning")
	}

	user.UpdateCredential(credential)
	datastore.SaveUser(user)

	t, err := datastore.GenSessionID()
	if err != nil {
		slog.ErrorContext(r.Context(), "can't generate session id", "err", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "login failed")
		return
	}

	datastore.SaveSession(t, webauthn.SessionData{
		Expires: time.Now().Add(time.Hour),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    t,
		Path:     "/",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // TODO: SameSiteStrictMode maybe?
	})

	w.Header().Set("HX-Reswap", "innerHTML")
	indexTemplate.ExecuteTemplate(w, "form", "login successful")
}

func PrivatePage(w http.ResponseWriter, r *http.Request) {
	// just show "Hello, World!" for now
	_, _ = w.Write([]byte("Hello, World!"))
}

func LoggedInMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: url to redirect to should be passed as a parameter

		sid, err := r.Cookie("sid")
		if err != nil {
			slog.DebugContext(r.Context(), "redirecting", "err", err.Error())
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		session, ok := datastore.GetSession(sid.Value)
		if !ok {
			slog.DebugContext(r.Context(), "redirecting", "err", "session not found")
			http.SetCookie(w, &http.Cookie{
				Name:  "lid",
				Value: "",
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if session.Expires.Before(time.Now()) {
			slog.DebugContext(r.Context(), "redirecting", "err", "session expired")
			http.SetCookie(w, &http.Cookie{
				Name:  "lid",
				Value: "",
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}
