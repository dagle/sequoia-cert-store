#[allow(non_upper_case_globals, dead_code)] mod keyring {
    use std::path::Path;
    use anyhow::Result;
    use sequoia_openpgp as openpgp;
    use openpgp::parse::Parse;

    pub struct Cert {
        pub filename: &'static str,
        pub base: &'static str,
        pub fingerprint: &'static str,
        pub subkeys: &'static [&'static str],
        pub userids: &'static [&'static str],
    }
    impl Cert {
        pub fn bytes(&self) -> Vec<u8> {
            let filename = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join(self.filename);
            std::fs::read(filename).expect("exists")
        }
        pub fn to_cert(&self) -> Result<openpgp::Cert> {
            openpgp::Cert::from_bytes(&self.bytes())
        }
    }

    pub const certs: &[Cert] = &[
        // alice
        Cert {
            filename: "data/alice.pgp",
            base: "alice",
            fingerprint: "30505BCEB7403A1BBFA9DBF0BFBE63567B4BA57A",
            subkeys: &[
                "662F03FC47C05D070B53A93AD5A5048A71CD012A",
                "A6D92948A7ADEB809F04202F1CF1943DFE153D1E",
                "5989D7BE9908AE24799DF6CFBE678043781349F1",
            ],
            userids: &[
                "<alice@beispiel.de>",
                "<alice@example.org>",
            ],
        },
        // alice2
        Cert {
            filename: "data/alice2.pgp",
            base: "alice2",
            fingerprint: "23CFE49D4BB7A0AA83619C147E716FFE77DF170A",
            subkeys: &[
            ],
            userids: &[
                "<alice@example.org>",
                "<alice@verein.de>",
            ],
        },
        // alice2_adopted_alice
        Cert {
            filename: "data/alice2-adopted-alice.pgp",
            base: "alice2_adopted_alice",
            fingerprint: "23CFE49D4BB7A0AA83619C147E716FFE77DF170A",
            subkeys: &[
                "662F03FC47C05D070B53A93AD5A5048A71CD012A",
                "5989D7BE9908AE24799DF6CFBE678043781349F1",
            ],
            userids: &[
                "<alice@example.org>",
                "<alice@verein.de>",
            ],
        },
        // bob
        Cert {
            filename: "data/bob.pgp",
            base: "bob",
            fingerprint: "9994DBF9D34E88E2A21D0CE8E79C9395A1004BB0",
            subkeys: &[
                "7E01441CBF6FAB5C4AB457E2FBD6F5322354B331",
            ],
            userids: &[
                "<bob@example.org>",
            ],
        },
        // carol
        Cert {
            filename: "data/carol.pgp",
            base: "carol",
            fingerprint: "E9C6EFC0E39CE6F9DF5274E7E362D45C7FF7B654",
            subkeys: &[
                "CD22D4BD99FF10FDA11A83D4213DCB92C95346CE",
            ],
            userids: &[
                "<carol@club.org>",
                "<carol@verein.de>",
            ],
        },
        // david
        Cert {
            filename: "data/david.pgp",
            base: "david",
            fingerprint: "A82BC944220BD5EBECC4D42883F74A0EAC207446",
            subkeys: &[
                "DF674FBAC52E00F0E6E48436481D2E18158FB594",
                "CD22D4BD99FF10FDA11A83D4213DCB92C95346CE",
            ],
            userids: &[
                "<david@example.org>",
            ],
        },
        // ed
        Cert {
            filename: "data/ed.pgp",
            base: "ed",
            fingerprint: "0C346B2B6241263F64E9C7CF1EA300797258A74E",
            subkeys: &[
                "0C346B2B6241263F64E9C7CF1EA300797258A74E",
            ],
            userids: &[
                "<ed@example.org>",
            ],
        },
        // halfling_signing
        Cert {
            filename: "data/halfling-signing.pgp",
            base: "halfling_signing",
            fingerprint: "D58E047C05D115EA4F3D1A98A67A733127BBE804",
            subkeys: &[
                "69669E91C8D5C546D442FB246FE6D4751AC09E15",
                "9DCDA2A95A17B728D6A5115EFF5C6582E4D14B68",
            ],
            userids: &[
                "<regis@pup.com>",
                "Halfling <signing@halfling.org>",
            ],
        },
        // halfling_encryption
        Cert {
            filename: "data/halfling-encryption.pgp",
            base: "halfling_encryption",
            fingerprint: "D58E047C05D115EA4F3D1A98A67A733127BBE804",
            subkeys: &[
                "69669E91C8D5C546D442FB246FE6D4751AC09E15",
                "CC4EFA3BFAB8E92A54CDEA3F3DC7543293DD4E53",
            ],
            userids: &[
                "<regis@pup.com>",
                "Halfling <encryption@halfling.org>",
            ],
        },
        // hans_puny_code
        Cert {
            filename: "data/hans-puny-code.pgp",
            base: "hans_puny_code",
            fingerprint: "F6675D0E4DA40823715C4811B89491F07D08E4F8",
            subkeys: &[
                "3F60EA0AEBC13E290939A080DB1F5F11C17CB2D4",
            ],
            userids: &[
                "Hans <hans@xn--bcher-kva.tld>",
            ],
        },
        // steve
        Cert {
            filename: "data/steve.pgp",
            base: "steve",
            fingerprint: "217E256E176719A5452EDFF935AADEC66B56585B",
            subkeys: &[
                "32C5820540308752B7092EE5B596B656FD8F700B",
            ],
            userids: &[
                "Steve <steve@sub.company.com>",
            ],
        },
        // una
        Cert {
            filename: "data/una.pgp",
            base: "una",
            fingerprint: "119B01460659D8EF3732BEC271424ADE3EC61BBC",
            subkeys: &[
                "EE58C32E3D2336F223BD89CED0BE447BF39B439F",
            ],
            userids: &[
                "Una <una@company.com>",
            ],
        },
    ];
    pub const alice: &Cert = &certs[0];
    pub const alice2: &Cert = &certs[1];
    pub const alice2_adopted_alice: &Cert = &certs[2];
    pub const bob: &Cert = &certs[3];
    pub const carol: &Cert = &certs[4];
    pub const david: &Cert = &certs[5];
    pub const ed: &Cert = &certs[6];
    pub const halfling_signing: &Cert = &certs[7];
    pub const halfling_encryption: &Cert = &certs[8];
    pub const hans_puny_code: &Cert = &certs[9];
    pub const steve: &Cert = &certs[10];
    pub const una: &Cert = &certs[11];
} // mod keyring
