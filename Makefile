

all:
	@echo "Compilación y ejecución de la práctica"

clean:
	@echo "Limpiando..."i
	@clear

server: clean
	@python3 serv7.py

server_daemon: clean
	@python3 Server_code.py -d

client: clean
	-@python3 cli7.py -u "Celiaco Falso" -c 1234

client2: clean
	-@python3 cli7.py -u "Pepito" -c 1234
