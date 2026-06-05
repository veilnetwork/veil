examples/ovl_proto.py — библиотека протокола
Полная реализация OVL1 IPC: encode/decode заголовков, OvlClient с методами bind() / send() / recv().

examples/chat_server.py — получатель

python3 examples/chat_server.py ~/.veil/app.sock
# ждёт сообщений, печатает sender node_id + текст
examples/chat_client.py — отправитель

# Узнать node_id ноды B:
veil-cli node show

# Отправить с ноды A:
python3 examples/chat_client.py <64-hex-node-id-B> "привет от A"
Как запустить полный тест

# Нода A: ~/.veil/app.sock
# Нода B: ~/.veil-b/app.sock  (другой config, другой порт)

# Терминал 1 — слушать на ноде B
python3 examples/chat_server.py ~/.veil-b/app.sock

# Терминал 2 — отправить с ноды A
veil-cli --config ~/.veil-b/config.yml node show  # получить node_id B
python3 examples/chat_client.py <node_id_B> "hello"
Требование: ноды должны быть подключены к сети. Прямые пиры работают напрямую; multi-hop через промежуточные ноды поддерживается через RouteCache и DELIVERY_FORWARD relay (реализовано в Эпике 50).