run:
	cargo build --target aarch64-unknown-linux-musl
	multipass exec gpi -- sudo /gpi/aarch64-unknown-linux-musl/debug/gpi --ns ns2 --eth enp0s1
