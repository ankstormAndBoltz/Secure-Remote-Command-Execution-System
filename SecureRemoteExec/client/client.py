import socket
from auth.auth_system import verify_user
from .logger import write_log


SERVER_IP = "127.0.0.1"
SERVER_PORT = 5000


def login():
    print("=== Secure Remote Client Login ===")

    username = input("Username: ")
    password = input("Password: ")

    if verify_user(username, password):
        print("Login Successful ✅")
        write_log(username, SERVER_IP, "LOGIN", "SUCCESS")

        return username
    else:
        print("Login Failed ❌")
        write_log(username, SERVER_IP, "LOGIN", "FAILED")

        return None


def connect_to_server(username):
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, SERVER_PORT))

        print("Connected to server")

        while True:
            command = input("Enter command (or exit): ")

            if command.lower() == "exit":
                break

            client.send(command.encode())

            output = client.recv(4096).decode()
            print(output)

            write_log(username, SERVER_IP, command, "EXECUTED")


        client.close()

    except Exception as e:
        print("Connection error:", e)


def main():
    user = login()

    if user:
        connect_to_server(user)
    else:
        print("Exiting program")


if __name__ == "__main__":
    main()

