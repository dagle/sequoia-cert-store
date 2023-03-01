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
- halfling-encryption.pgp:
    Fingerprint: D58E047C05D115EA4F3D1A98A67A733127BBE804
      Key flags: certification
         Subkey: 9DCDA2A95A17B728D6A5115EFF5C6582E4D14B68
      Key flags: signing
         Subkey: CC4EFA3BFAB8E92A54CDEA3F3DC7543293DD4E53
      Key flags: transport encryption, data-at-rest encryption
         UserID: <regis@pup.com>
         UserID: Halfling <encryption@halfling.org>
- halfling-signing.pgp:
    Fingerprint: D58E047C05D115EA4F3D1A98A67A733127BBE804
      Key flags: certification
         Subkey: 69669E91C8D5C546D442FB246FE6D4751AC09E15
      Key flags: authentication
         Subkey: 9DCDA2A95A17B728D6A5115EFF5C6582E4D14B68
      Key flags: signing
         UserID: <regis@pup.com>
         UserID: Halfling <signing@halfling.org>
- hans-puny-code.pgp:
    Fingerprint: F6675D0E4DA40823715C4811B89491F07D08E4F8
      Key flags: certification
         Subkey: 3F60EA0AEBC13E290939A080DB1F5F11C17CB2D4
      Key flags: signing
         UserID: Hans <hans@xn--bcher-kva.tld>
- steve.pgp:
    Fingerprint: 217E256E176719A5452EDFF935AADEC66B56585B
      Key flags: certification
         Subkey: 32C5820540308752B7092EE5B596B656FD8F700B
      Key flags: signing
         UserID: Steve <steve@sub.company.com>
- una.pgp:
    Fingerprint: 119B01460659D8EF3732BEC271424ADE3EC61BBC
      Key flags: certification
         Subkey: EE58C32E3D2336F223BD89CED0BE447BF39B439F
      Key flags: signing
         UserID: Una <una@company.com>
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

halfling: Two versions of the same certificate.  Both have the same
authentication subkey, one has a signing subkey, the other an
encryption subkey.  Likewise, both have one User ID in common
(regis@pup.com) and a second User ID ('Halfling
<encryption@halfling.org>' and 'Halfling <signing@halfling.org>',
respectively).

hans: A certificate with an email address that uses puny code.

una: A certificate with an email address for the domain `company.com`.

steve: A certificate with an email address for a subdomain of
`sub.company.com`.
