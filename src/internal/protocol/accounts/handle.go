package accounts

// Handle builds an account's canonical handle per 11.4 from its current
// canonical username (11.6) and the canonical hostname of the instance that
// hosts it (13.4).
//
// The username is normalized rather than validated, because a handle reports an
// account that exists: 11.6 makes the folded name the only form an instance
// stores or compares, so a name registered before the grammar was enforced
// still has to render.
//
// The handle routes and displays an account; it is not an identity. Two
// handles sharing a username on different hostnames name different accounts,
// and a hostname identifies no instance (13.4.1), so callers that act on
// identity use account_id or the identity public key instead.
func Handle(username, domain string) string {
	return "@" + NormalizeUsername(username) + ":" + domain
}
