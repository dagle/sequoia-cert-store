certs = data/alice.pgp \
	data/alice2.pgp \
	data/alice2-adopted-alice.pgp \
	data/bob.pgp \
	data/carol.pgp \
	data/david.pgp \
	data/ed.pgp \
	data/halfling-signing.pgp \
	data/halfling-encryption.pgp \
	data/hans-puny-code.pgp \
	data/steve.pgp \
	data/una.pgp


keyring.rs keyring.pgp: $(certs) cert2rust.sh
	./cert2rust.sh $(certs) > keyring.rs
	sq keyring join $(certs) > keyring.pgp
