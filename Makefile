SHELL := powershell

server:
	@cargo watch --clear --ignore cliplink-cli -x "run --bin cliplink-server"

cli:
	@cargo watch --clear --ignore cliplink-server -x "run --bin cliplink-cli"
