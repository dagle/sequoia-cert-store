#! /bin/bash

set -e

echo "#[allow(non_upper_case_globals, dead_code)] mod keyring {
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
            let filename = Path::new(env!(\"CARGO_MANIFEST_DIR\"))
                .join(\"tests\")
                .join(self.filename);
            std::fs::read(filename).expect(\"exists\")
        }
        pub fn to_cert(&self) -> Result<openpgp::Cert> {
            openpgp::Cert::from_bytes(&self.bytes())
        }
    }
"

for file in "$@" "EOF!"
do
    base=${file%-priv.pgp}
    base=${base%.pgp}
    base=${base#*/}
    base=$(echo $base | sed 's/-/_/g')

    echo "FILE:$file:$base"
    if test "x$file" != "xEOF!"
    then
        sq packet dump "$file"
    fi
done | awk -F '[ \t]*:[ \t]*' '
  BEGIN {
    # Initialize the arrays.
    delete certs[0];
    delete fprs[0];
    delete userids[0];

    print "    pub const certs: &[Cert] = &["
  }
  END {
    print "    ];"

    for (i = 0; i < length(certs) - 1; i ++) {
      print "    pub const "certs[i]": &Cert = &certs["i"];";
    }
  }

  $1 ~ /^FILE$/ {
    # Print the pending record.
    if (length(fprs) > 0) {
      print "        // "base
      print "        Cert {"
      print "            filename: \""file"\","
      print "            base: \""base"\","
      print "            fingerprint: \""fprs[0]"\","
      print "            subkeys: &[";
      for(i = 1; i < length(fprs); i ++) {
        print "                \""fprs[i]"\","
      }
      print "            ],";
      print "            userids: &[";
      for(i = 0; i < length(userids); i ++) {
        print "                \""userids[i]"\","
      }
      print "            ],"
      print "        },"
    }

    # Reinitialize the state.
    delete fprs;
    delete userids;
    # Make sure the arrays are interrupted as arrays and not scalars
    # (need for length(fprs).
    delete fprs[0];
    delete userids[0];

    file=$2;
    base=$3;
    certs[length(certs)] = base;
  }

  $1 ~ /^ *Fingerprint$/ {
    fprs[length(fprs)] = $2;
  }
  $1 ~ /^ *Value$/ {
    userids[length(userids)] = $2;
  }
'

echo "} // mod keyring"

