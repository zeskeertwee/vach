# # Variables
EXCLUDE=test.sh
ARTIFACTS="keypair.sk keypair.pk keypair.kp signed.vach custom.vach encrypted.vach"
VACH="cargo run -q --release --"

# # Delete any previous artifacts
rm -f $ARTIFACTS

# # Prelude
echo "Starting vach-cli tests..."
echo
sleep 1s

# # Cargo tests
cargo check -q
cargo build -q --release

# # Create simple archive with simple input, no compression only signatures
$VACH pack -o signed.vach -r ./ -c never -a -x $EXCLUDE

# # Split the resulting keypair
$VACH split -i keypair.kp
$VACH list -i signed.vach

# # Generate a compressed archive with custom magic
$VACH pack -o custom.vach -m CSTOM -i GamerProfile.xml -x $EXCLUDE
$VACH list -i custom.vach -m CSTOM

# # Generate an encrypted, signed and compressed archive
$VACH pack -o encrypted.vach -d lolcalt -ea -c always -s keypair.sk
$VACH list -i encrypted.vach

# Unpack the encrypted archive
$VACH unpack -i encrypted.vach -k keypair.kp

# # Delete any previous artifacts
rm -f $ARTIFACTS