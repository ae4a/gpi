run:
	cargo build --target aarch64-unknown-linux-musl
	multipass transfer ./target/aarch64-unknown-linux-musl/debug/gpi gpi:/home/ubuntu/gpi
	multipass exec gpi -- sudo ./gpi --eth enp0s1 --sni
