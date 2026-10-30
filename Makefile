run:
	cargo build --target aarch64-unknown-linux-musl
	multipass transfer ./target/aarch64-unknown-linux-musl/debug/gpi gpi:/home/ubuntu/gpi
	multipass exec gpi -- sudo ./gpi --ns ns2 --eth enp0s1
