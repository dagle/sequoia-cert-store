The certificates:

```
$ for i in $(ls -1 *.pgp | grep -v -- -priv.pgp | sort); do echo; echo "- $i:"; sq inspect $i; done | grep -E '^- |Fingerprint|Key flags|Subkey|UserID'
- alice2-adopted-alice.pgp:
    Fingerprint: 23CFE49D4BB7A0AA83619C147E716FFE77DF170A
      Key flags: certification
         Subkey: 662F03FC47C05D070B53A93AD5A5048A71CD012A
      Key flags: signing
         Subkey: 5989D7BE9908AE24799DF6CFBE678043781349F1
      Key flags: transport encryption, data-at-rest encryption
         UserID: <alice@example.org>
         UserID: <alice@verein.de>
- alice2.pgp:
    Fingerprint: 23CFE49D4BB7A0AA83619C147E716FFE77DF170A
      Key flags: certification
         UserID: <alice@example.org>
         UserID: <alice@verein.de>
- alice.pgp:
    Fingerprint: 30505BCEB7403A1BBFA9DBF0BFBE63567B4BA57A
      Key flags: certification
         Subkey: 662F03FC47C05D070B53A93AD5A5048A71CD012A
      Key flags: signing
         Subkey: A6D92948A7ADEB809F04202F1CF1943DFE153D1E
      Key flags: authentication
         Subkey: 5989D7BE9908AE24799DF6CFBE678043781349F1
      Key flags: transport encryption, data-at-rest encryption
         UserID: <alice@beispiel.de>
         UserID: <alice@example.org>
- bob.pgp:
    Fingerprint: 9994DBF9D34E88E2A21D0CE8E79C9395A1004BB0
      Key flags: certification
         Subkey: 7E01441CBF6FAB5C4AB457E2FBD6F5322354B331
      Key flags: authentication
         UserID: <bob@example.org>
- carol.pgp:
    Fingerprint: E9C6EFC0E39CE6F9DF5274E7E362D45C7FF7B654
      Key flags: certification
         Subkey: CD22D4BD99FF10FDA11A83D4213DCB92C95346CE
      Key flags: authentication
         UserID: <carol@club.org>
         UserID: <carol@verein.de>
- david-2.pgp:
    Fingerprint: A82BC944220BD5EBECC4D42883F74A0EAC207446
      Key flags: certification
         Subkey: DF674FBAC52E00F0E6E48436481D2E18158FB594
      Key flags: authentication
         UserID: <david@example.org>
- david.pgp:
    Fingerprint: A82BC944220BD5EBECC4D42883F74A0EAC207446
      Key flags: certification
         Subkey: DF674FBAC52E00F0E6E48436481D2E18158FB594
      Key flags: authentication
         UserID: <david@example.org>
- ed.pgp:
    Fingerprint: 0C346B2B6241263F64E9C7CF1EA300797258A74E
      Key flags: certification
         Subkey: 0C346B2B6241263F64E9C7CF1EA300797258A74E
      Key flags: certification
         UserID: <ed@example.org>
```

alice: A normal certificate with two User IDs.  Shares one with alice.

alice2: A normal certificate with two User IDs.  Shares one with
alice.

alice2-adopted-alice: alice2, but adopts the signing and encryption
subkeys from alice.  (Note: does *not* adopt the authentication
subkey.)

bob: A normal certificate with two User IDs.

carol: A normal certificate with two User IDs.

david: A normal certificate, but with a copy of one of carol's subkeys
(CD22D4BD99FF10FDA11A83D4213DCB92C95346CE).  That is, the subkey is
appended to david's certificate, but there is no binding signature.

ed: An unusual certificate: his primary key is also a subkey on his
certificate!

hans: A certificate with an email address that uses puny code.

una: A certificate with an email address for the domain `company.com`.

steve: A certificate with an email address for a subdomain of
`sub.company.com`.
