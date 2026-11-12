// Command gophkeeper is the GophKeeper client: a CLI password manager that
// encrypts data on the client and syncs it through the GophKeeper server.
//
// Usage:
//
//	gophkeeper register LOGIN [--server ADDRESS] [--ca FILE] [--raw]
//	gophkeeper login LOGIN [--server ADDRESS] [--ca FILE] [--raw]
//	gophkeeper unlock [--raw]
//	gophkeeper change-password
//	gophkeeper sync
//	gophkeeper add login --name NAME [--meta TEXT] [--login LOGIN] [--password PASSWORD]
//	gophkeeper add text --name NAME [--meta TEXT] [--text TEXT]
//	gophkeeper add file --name NAME [--meta TEXT] --file PATH
//	gophkeeper add card --name NAME [--meta TEXT] --number NUMBER [--holder NAME] --expiry MM/YY [--cvv CVV]
//	gophkeeper list
//	gophkeeper show ID [--out PATH]
//	gophkeeper edit ID [field flags]
//	gophkeeper delete ID
//	gophkeeper lock
//	gophkeeper logout [--force]
//	gophkeeper version
//
// The version and build date are set at build time with
// -ldflags "-X main.version=... -X main.buildDate=...".
package main
