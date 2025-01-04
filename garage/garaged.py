from gpiozero import DigitalOutputDevice
import time
import os, os.path
import socket

SOCKET_PATH = "/home/byerl/run/garage.s"

if os.path.exists(SOCKET_PATH):
	os.remove(SOCKET_PATH)

server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(SOCKET_PATH)

CMD_DOOR_OPEN_CLOSE = 0
CMD_SERVER_STOP = 255

bays = []
bays.append(DigitalOutputDevice(12, initial_value=False))
bays.append(DigitalOutputDevice(13, initial_value=False))

def toggle_door(bay=0):
	if bay < len(bays) and bay >= 0:
		print(f"Toggling bay {bay}")
		door_opener = bays[bay]
		door_opener.on()
		time.sleep(0.1)
		door_opener.off()

server_stop_flag = False
while not server_stop_flag:
	server.listen(1)
	conn, address = server.accept()
	data = conn.recv(128)
	if data and len(data) > 0:
		cmd = int.from_bytes(data[0:1])
		if cmd == CMD_DOOR_OPEN_CLOSE:
			bay = int.from_bytes(data[1:2]) if len(data) > 1 else 0
			toggle_door(bay=bay)
		elif cmd == CMD_SERVER_STOP:
			server_stop_flag = True
	conn.close()
