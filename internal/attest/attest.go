// Package attest verifies a Sigstore bundle for a package file with sigstore-go and
// returns the claims it establishes.
package attest

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/torstei/apt-attest/internal/policy"
)

type Verifier struct {
	v *verify.Verifier
}

// NewVerifier requires what Sigstore's public-good instance provides: a certificate
// from Fulcio with an embedded SCT, an entry in Rekor with a verified inclusion proof
// and checkpoint, and a trusted time (Rekor's integrated time or a signed timestamp)
// inside the certificate's validity.
func NewVerifier(tr root.TrustedMaterial) (*Verifier, error) {
	v, err := verify.NewVerifier(tr,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, err
	}
	return &Verifier{v: v}, nil
}

// Verify checks the bundle cryptographically and that its in-toto statement has the
// file's SHA256 as a subject, and returns its claims. It does not judge the claims:
// the identity check is policy.Compare, run on every use, including cached claims.
func (v *Verifier) Verify(bundleJSON []byte, sha256Hex string) (policy.Claims, error) {
	var claims policy.Claims
	digest, err := hex.DecodeString(sha256Hex)
	if err != nil || len(digest) != 32 {
		return claims, fmt.Errorf("bad SHA256 %q", sha256Hex)
	}
	var b bundle.Bundle
	// The parse error quotes the input, which may not be a bundle at all.
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return claims, errors.New("not a Sigstore bundle")
	}
	if b.GetDsseEnvelope() == nil {
		return claims, errors.New("bundle holds no in-toto attestation (no DSSE envelope)")
	}

	res, err := v.v.Verify(&b, verify.NewPolicy(
		verify.WithArtifactDigest("sha256", digest),
		verify.WithoutIdentitiesUnsafe(),
	))
	if err != nil {
		if subjects := unverifiedSubjects(&b); subjects != "" && !strings.Contains(subjects, sha256Hex) {
			return claims, fmt.Errorf("bundle is for %s, not this file (sha256:%s)", subjects, sha256Hex)
		}
		return claims, fmt.Errorf("bundle does not verify: %w", err)
	}
	if res.Signature == nil || res.Signature.Certificate == nil {
		return claims, errors.New("bundle is not signed with a Fulcio certificate")
	}
	if res.Statement == nil {
		return claims, errors.New("bundle holds no in-toto statement")
	}

	c := res.Signature.Certificate
	claims = policy.Claims{
		Issuer:                          c.Issuer,
		SourceRepositoryURI:             c.SourceRepositoryURI,
		SourceRepositoryIdentifier:      c.SourceRepositoryIdentifier,
		SourceRepositoryOwnerIdentifier: c.SourceRepositoryOwnerIdentifier,
		BuildSignerURI:                  c.BuildSignerURI,
		SourceRepositoryRef:             c.SourceRepositoryRef,
		RunnerEnvironment:               c.RunnerEnvironment,
		PredicateType:                   res.Statement.GetPredicateType(),
	}
	for _, s := range res.Statement.GetSubject() {
		claims.Subjects = append(claims.Subjects, policy.Subject{Name: s.GetName(), SHA256: s.GetDigest()["sha256"]})
	}
	return claims, nil
}

// unverifiedSubjects reads the statement's subjects without verifying anything, only
// to say in an error message which file a bundle was made for.
func unverifiedSubjects(b *bundle.Bundle) string {
	env := b.GetDsseEnvelope()
	var st struct {
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if env == nil || json.Unmarshal(env.GetPayload(), &st) != nil {
		return ""
	}
	var out []string
	for _, s := range st.Subject {
		out = append(out, s.Name+" sha256:"+s.Digest["sha256"])
	}
	return strings.Join(out, ", ")
}
