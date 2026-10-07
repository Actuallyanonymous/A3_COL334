# Optional. `make` byte-compiles the programs; it does not need a network.
.PHONY: all
all:
	python3 -m py_compile src/wire.py src/tcp_conn.py src/http_client.py src/http_server.py
