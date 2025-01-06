import socket
import zipfile
import os
import subprocess  # 명령어 실행을 위한 모듈

def receive_file(client_socket, save_path, file_size):
    
    received_size = 0  # 수신한 크기 초기화

    with open(save_path, 'wb') as f:
        while received_size < file_size:
            data = client_socket.recv(1024)
            if not data:
                break
            f.write(data)
            received_size += len(data)  # 수신한 크기 업데이트

    print(f"File received successfully. Total received size: {received_size} bytes.")

def unzip_file(zip_path, extract_to):
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    print(f"Files extracted to {extract_to}")

def delete_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Deleted file: {file_path}")
    else:
        print(f"File not found: {file_path}")

def execute_command(command):
    try:
        # 명령어 실행 후 결과 반환
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
        print(f"Command output:\n{output}")
        return output
    except Exception as e:
        print(f"Command execution error: {e}")
        return str(e)

    # 리스트를 문자열로 변환
    characters_str = ''.join(characters)
    numbers_str = ''.join(numbers)


def start_client():
    server_ip = input("Enter the server IP address: ")  # 서버 IP 입력
    server_port = 10000  # 포트 번호 고정
    current_directory = os.getcwd()
    save_path = os.path.join(current_directory, 'received_folder.zip')
    extract_to = current_directory
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((server_ip, server_port))
            while True:
                # 서버에서 전송된 명령 수신
                command = client_socket.recv(1024).decode()  # 데이터를 문자열로 변환
                data = ""
                if command.startswith("FILE_TRANSFER"):
                    # 공백을 기준으로 명령어와 파일 크기 분리
                    parts = command.split()
                    data = parts[0]  # FILE_TRANSFER 명령어
                    file_size = int(parts[1])  # 파일 크기

                if data == "FILE_TRANSFER":
                    # 파일 전송 모드로 전환
                    receive_file(client_socket, save_path, file_size)
                    unzip_file(save_path, extract_to)
                    delete_file(save_path)

                elif command.startswith("EXECUTE"):
                    # 명령어 수행
                    exec_command = command.split("EXECUTE ", 1)[1]
                    print(f"Executing command: {exec_command}")
                    output = execute_command(exec_command)
                    # 명령어 결과 서버에 전송하지 않음
                elif command == "SERVER_SHUTDOWN":
                    print("Server is shutting down. Closing connection.")
                    break  # 서버가 종료되었으므로 연결 종료
                else:
                    print(f"Unknown command: {command}")
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    start_client()