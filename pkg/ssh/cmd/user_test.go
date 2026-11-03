package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/matryer/is"
	"golang.org/x/crypto/ssh"
)

// TestUserCreateSplitKey is the regression test for issue #750. SSH splits the
// remote command on whitespace and drops the client's quoting, so
//
//	user create NAME -k ssh-ed25519 AAAA...
//
// arrives as the flag value "ssh-ed25519" plus a trailing positional
// argument. The command must reassemble and accept the key.
func TestUserCreateSplitKey(t *testing.T) {
	is := is.New(t)
	ctx, be := newAuthTestContext(t)
	adminCtx := withUser(t, ctx, be, "boss", true)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)
	pub, err := ssh.NewPublicKey(priv.Public())
	is.NoErr(err)
	keyType, keyBody, _ := strings.Cut(strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), " ")

	// Split exactly as SSH would: the flag takes the key type, the body
	// becomes a separate positional argument.
	is.NoErr(runUser(t, adminCtx, "create", "split", "-k", keyType, keyBody))

	user, err := be.User(adminCtx, "split")
	is.NoErr(err)
	is.Equal(len(user.PublicKeys()), 1)
}
