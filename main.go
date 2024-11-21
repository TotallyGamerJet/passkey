package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
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

type PasskeyUser interface {
	webauthn.User
	AddCredential(*webauthn.Credential)
	UpdateCredential(*webauthn.Credential)
}

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
	proto := getEnv("PROTO", "https")
	host := getEnv("HOST", "localhost")
	port := getEnv("PORT", ":8080")
	origin := fmt.Sprintf("%s://%s%s", proto, host, port)

	log.Printf("[INFO] make webauthn config")
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",    // Display Name for your site
		RPID:          host,             // Generally the FQDN for your site
		RPOrigins:     []string{origin}, // The origin URLs allowed for WebAuthn
	}

	log.Printf("[INFO] create webauthn")
	var err error
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Printf("[FATA] %s", err.Error())
		os.Exit(1)
	}

	log.Printf("[INFO] create datastore")
	datastore = NewInMem(log.Default())

	log.Printf("[INFO] register routes")
	// Serve the web files
	http.Handle("/src/", http.StripPrefix("/src/", http.FileServer(http.Dir("./web"))))
	http.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		_ = indexTemplate.Execute(w, nil)
	})
	// Add auth the routes
	http.HandleFunc("GET /register", BeginRegistration)
	http.HandleFunc("POST /register", FinishRegistration)
	http.HandleFunc("GET /login", BeginLogin)
	http.HandleFunc("POST /login", FinishLogin)

	http.Handle("/private", LoggedInMiddleware(http.HandlerFunc(PrivatePage)))

	// Start the server
	log.Printf("[INFO] start server at %s", origin)
	// Generate self-signed certificates for development
	// go run $GOROOT/src/crypto/tls/generate_cert.go --host="localhost"
	if err := http.ListenAndServeTLS(port, "cert.pem", "key.pem", nil); err != nil {
		fmt.Println(err)
	}
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin registration ----------------------\\")
	if err := r.ParseForm(); err != nil {
		log.Fatal(err)
		return
	}
	email, err := mail.ParseAddress(r.FormValue("email"))
	if err != nil {
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "incorrect email format")
		return
	}
	user := datastore.GetOrCreateUser(email.Address) // Find or create the new user

	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		log.Println(fmt.Sprintf("can't begin registration: %s", err.Error()))
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}

	// Make a session key and store the sessionData values
	t, err := datastore.GenSessionID()
	if err != nil {
		log.Printf("[ERRO] can't generate session id: %s", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "incorrect email format")
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
		SameSite: http.SameSiteStrictMode, // TODO: SameSiteStrictMode maybe?
	})
	optionsJson, err := json.Marshal(options)
	if err != nil {
		log.Println(fmt.Sprintf("JSON marshaling of options failed: %s", err.Error()))
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
	// Get the session key from cookie
	sid, err := r.Cookie("rid")
	if err != nil {
		log.Printf("[ERROR] can't get session id: %s", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}
	defer http.SetCookie(w, &http.Cookie{
		Name:  "rid",
		Value: "",
	})
	if err = r.ParseForm(); err != nil {
		log.Printf("[ERROR] can't parse form: %s", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}
	data, err := base64.StdEncoding.DecodeString(r.FormValue("data"))
	if err != nil {
		log.Printf("[ERROR] can't decode form data: %s", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}
	// Get the session data stored from the function above
	session, _ := datastore.GetSession(sid.Value) // FIXME: cover invalid session

	// In out example username == userID, but in real world it should be different
	user := datastore.GetOrCreateUser(string(session.UserID)) // Get the user
	cred, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(data))
	if err != nil {
		log.Printf("[ERROR] can't parse body: %s", err.Error())
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}
	//credential, err := webAuthn.FinishRegistration(user, session, r)
	credential, err := webAuthn.CreateCredential(user, session, cred)
	if err != nil {
		msg := fmt.Sprintf("can't finish registration: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		w.Header().Set("HX-Reswap", "innerHTML")
		indexTemplate.ExecuteTemplate(w, "form", "registration failed")
		return
	}

	// If creation was successful, store the credential object
	user.AddCredential(credential)
	datastore.SaveUser(user)
	// Delete the session data
	datastore.DeleteSession(sid.Value)
	log.Printf("[INFO] finish registration ----------------------/")
	JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] begin login ----------------------\\")

	if err := r.ParseForm(); err != nil {
		log.Fatal(err)
		return
	}
	email, err := mail.ParseAddress(r.FormValue("email"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusOK)
		return
	}

	user := datastore.GetOrCreateUser(email.Address) // Find the user

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		msg := fmt.Sprintf("can't begin login: %s", err.Error())
		log.Printf("[ERRO] %s", msg)
		JSONResponse(w, msg, http.StatusBadRequest)

		return
	}

	// Make a session key and store the sessionData values
	t, err := datastore.GenSessionID()
	if err != nil {
		log.Printf("[ERRO] can't generate session id: %s", err.Error())

		panic(err) // TODO: handle error
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
		fmt.Fprintf(w, "login failed")
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
	// Get the session key from cookie
	lid, err := r.Cookie("lid")
	if err != nil {
		fmt.Fprintf(w, "login failed")
		return
	}
	defer datastore.DeleteSession(lid.Value)
	defer http.SetCookie(w, &http.Cookie{
		Name:  "lid",
		Value: "",
	})

	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "login failed")
		return
	}
	data, err := base64.StdEncoding.DecodeString(r.FormValue("data"))
	if err != nil {
		fmt.Fprintf(w, "login failed")
		return
	}
	// Get the session data stored from the function above
	session, _ := datastore.GetSession(lid.Value) // FIXME: cover invalid session

	// In out example username == userID, but in real world it should be different
	user := datastore.GetOrCreateUser(string(session.UserID)) // Get the user

	cred, err := protocol.ParseCredentialRequestResponseBody(bytes.NewBuffer(data))
	if err != nil {
		panic(err)
	}
	credential, err := webAuthn.ValidateLogin(user, session, cred)
	if err != nil {
		log.Printf("[ERRO] can't finish login: %s", err.Error())
		panic(err)
	}

	// Handle credential.Authenticator.CloneWarning
	if credential.Authenticator.CloneWarning {
		log.Printf("[WARN] can't finish login: %s", "CloneWarning")
	}

	// If login was successful, update the credential object
	user.UpdateCredential(credential)
	datastore.SaveUser(user)

	// Add the new session cookie
	t, err := datastore.GenSessionID()
	if err != nil {
		log.Printf("[ERRO] can't generate session id: %s", err.Error())

		panic(err) // TODO: handle error
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

	log.Printf("[INFO] finish login ----------------------/")
	JSONResponse(w, "Login Success", http.StatusOK)
}

func PrivatePage(w http.ResponseWriter, r *http.Request) {
	// just show "Hello, World!" for now
	_, _ = w.Write([]byte("Hello, World!"))
}

// JSONResponse is a helper function to send json response
func JSONResponse(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// getEnv is a helper function to get the environment variable
func getEnv(key, def string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}

	return def
}

func LoggedInMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: url to redirect to should be passed as a parameter

		sid, err := r.Cookie("sid")
		if err != nil {
			http.Redirect(w, r, "/", http.StatusSeeOther)

			return
		}

		session, ok := datastore.GetSession(sid.Value)
		if !ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)

			return
		}

		if session.Expires.Before(time.Now()) {
			http.Redirect(w, r, "/", http.StatusSeeOther)

			return
		}

		next.ServeHTTP(w, r)
	})
}
