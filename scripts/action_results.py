import json
from os import path
import subprocess

login_file = '/etc/pam.d/login'
securetty_file = '/etc/securetty'
sshd_config_file = '/etc/ssh/sshd_config'

final_report = []

#[U-01] root 계정 원격 접속 제한  
def U01():  
    report_data = {
        "이름": "U-01",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }
    login_file = '/etc/pam.d/login'

    try:
        with open(login_file, 'r+') as f:
            lines = f.readlines()
            f.seek(0)
            found = False
            for line in lines:
                if 'pam_securetty.so' in line and not line.startswith('#'):
                    found = True
                    break
            if not found:
                f.write('auth required pam_securetty.so\n')
                report_data["조치결과"] = "조치 완료"
            else:
                report_data["조치결과"] = "이미 설정됨"
    except Exception as e:
        report_data["조치결과"] = "조치 실패"
        print(f"{login_file} 파일 수정 중 오류 발생: {e}")

    return report_data
    

#[U-04] 1.4 패스워드 파일 보호
def U04():
    report_data = {
        "이름": "U-04",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    shadow_file = "/etc/shadow"
    passwd_file = '/etc/passwd'

    if not os.path.isfile(shadow_file):
        report_data["조치결과"] = "취약"
    else:
        try:
            with open(passwd_file, 'r') as f:
                line = f.readline().split(':')
                if line[1] != 'x':
                    report_data["조치결과"] = "취약"
                else:
                    report_data["조치결과"] = "양호"
        except FileNotFoundError:
            report_data["조치결과"] = "취약"

    return report_data

#[U-05] root 홈, 패스 디렉터리 권한 및 패스 설정
def U05():
    report_data = {
        "이름": "U-05",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    env_list = subprocess.check_output('echo $PATH', shell=True).decode().strip()
    if '.' in env_list or '::' in env_list:
        report_data["조치결과"] = "취약"
    else:
        report_data["조치결과"] = "양호"

    return report_data

#[U-06] 파일 및 디렉터리 소유자 설정 자동화 조치
def U06():
    report_data = {
        "이름": "U-06",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현",
        "조치내용": []
    }

    try:
        result = subprocess.check_output('find / -nouser', shell=True).decode().strip()
        if result:
            report_data["조치결과"] = "취약"
        else:
            report_data["조치결과"] = "양호"
    except subprocess.CalledProcessError:
        report_data["조치결과"] = "취약"

    return report_data

#[U-07] /etc/passwd 파일 소유자 및 권한 자동화 조치
def U07():
    report_data = {
        "이름": "U-07",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현",
        "조치내용": []
    }

   status = os.stat('/etc/passwd')

    # 소유자 수정 (root로 변경)
    if status.st_uid != 0:
        os.system('chown root /etc/passwd')
        report_data["조치결과"] = "조치 완료"
    
    # 권한 수정 (644로 변경)
    perm = int(oct(status.st_mode)[-3:])
    if perm != 644:
        os.system('chmod 644 /etc/passwd')
        report_data["조치결과"] = "조치 완료"

    return report_data

#[U-08] /etc/shadow 파일 소유자 및 권한 자동화 조치
def U08():
    report_data = {
        "이름": "U-08",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현",
        "조치내용": []
    }

    shadow_file = '/etc/shadow'
    if os.path.isfile(shadow_file):
        status = os.stat(shadow_file)

        # 소유자 수정 (root로 변경)
        if status.st_uid != 0:
            os.system('chown root /etc/shadow')

        # 권한 수정 (400으로 변경)
        perm = int(oct(status.st_mode)[-3:])
        if perm != 400:
            os.system('chmod 400 /etc/shadow')

        report_data["조치결과"] = "조치 완료"
    else:
        report_data["조치결과"] = "취약"

    return report_data

#[U-09] /etc/hosts 파일 소유자 및 권한 자동화 조치
def U09():
    report_data = {
        "이름": "U-09",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현",
        "조치내용": []
    }

    status = os.stat('/etc/hosts')

    # 소유자 수정 (root로 변경)
    if status.st_uid != 0:
        os.system('chown root /etc/hosts')

    # 권한 수정 (600으로 변경)
    perm = int(oct(status.st_mode)[-3:])
    if perm != 600:
        os.system('chmod 600 /etc/hosts')

    report_data["조치결과"] = "조치 완료"

    return report_data

#[U-10] /etc/(x)inetd.conf 파일 소유자 및 권한 자동화 조치
def U10():
    report_data = {
        "이름": "U-10",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현",
        "조치내용": []
    }

    filename = None

    # 확인할 파일 경로 변수
    isInetd = os.path.isfile('/etc/inetd.conf')
    if isInetd:
        filename = '/etc/inetd.conf'

    isXinetd = os.path.isfile('/etc/xinetd.conf')
    if isXinetd:
        filename = '/etc/xinetd.conf'

    # 둘 다 없는 경우 처리
    if not isInetd and not isXinetd:
        report_data["조치결과"] = "취약"
        return report_data

    # 파일 상태 확인
    status = os.stat(filename)

    # 소유자 수정 (root로 변경)
    if status.st_uid != 0:
        os.system(f'chown root {filename}')

    # 권한 수정 (600으로 변경)
    perm = int(oct(status.st_mode)[-3:])
    if perm != 600:
        os.system(f'chmod 600 {filename}')

    report_data["조치결과"] = "조치 완료"

    return report_data

#[U-11] 2.7 /etc/syslog.conf 파일 소유자 및 권한 설정
def U11():
    report_data = {
        "이름": "U-11",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    filename = ''

    # /etc/syslog.conf 파일 존재 여부 확인
    isSyslog = path.isfile('/etc/syslog.conf')
    if isSyslog:
        filename = '/etc/syslog.conf'
    else:
        report_data["조치결과"] = "취약"

    # /etc/rsyslog.conf 파일 존재 여부 확인
    isRsyslog = path.isfile('/etc/rsyslog.conf')
    if isRsyslog:
        filename = '/etc/rsyslog.conf'
    else:
        report_data["조치결과"] = "취약"

    # 두 파일 모두 없는 경우
    if not isSyslog and not isRsyslog:
        return report_data

    # 파일 상태 확인
    status = stat(filename)

    # 소유자 확인 및 수정 (root로 변경)
    owner = status.st_uid
    if owner != 0:
        os.system(f'chown root {filename}')
        report_data["조치결과"] = "조치 완료"

    # 권한 확인 및 수정 (644로 변경)
    perm = int(oct(status.st_mode)[-3:])
    if perm != 644:
        os.system(f'chmod 644 {filename}')
        report_data["조치결과"] = "조치 완료"

    return report_data

#[U-12] 2.8 /etc/services 파일 소유자 및 권한 설정
def U12():
    report_data = {
        "이름": "U-12",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    # 파일 상태 확인
    status = stat('/etc/services')

    # 소유자 확인 및 수정 (root로 변경)
    owner = status.st_uid
    if owner != 0:
        os.system('chown root /etc/services')
        report_data["조치결과"] = "조치 완료"

    # 권한 확인 및 수정 (644 이하로 변경)
    perm = int(oct(status.st_mode)[-3:])
    if perm > 644:
        os.system('chmod 644 /etc/services')
        report_data["조치결과"] = "조치 완료"

    # 최종 상태 확인
    if report_data["조치결과"] == "":
        report_data["조치결과"] = "양호"

    return report_data   

# [U-13] 2.9 SUID, SGID, sticky bit 설정 및 권한 설정
def U13():
    report_data = {
        "이름": "U-13",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    SUID = 0o4000  # SUID 비트
    SGID = 0o2000  # SGID 비트

    # 불필요한 SUID/SGID 파일 목록
    files = [
        '/sbin/dump', '/sbin/restore', '/sbin/unix_chkpwd', '/usr/bin/at',
        '/usr/bin/lpq', '/usr/bin/lpq-lpd', '/usr/bin/lprm', '/usr/bin/lprm-lpd',
        '/usr/bin/newgrp', '/usr/sbin/lpc', '/usr/sbin/lpc-lpd', '/usr/sbin/traceroute'
    ]

    for file in files:
        if not os.path.isfile(file):
            continue

        # 파일 상태 확인
        status = os.stat(file)
        perm = int(oct(status.st_mode)[-4:])

        # SUID 비트 제거
        if perm & SUID:
            os.system(f'chmod -s {file}')
            print(f"SUID 비트가 제거되었습니다: {file}")

        # SGID 비트 제거
        if perm & SGID:
            os.system(f'chmod -s {file}')
            print(f"SGID 비트가 제거되었습니다: {file}")

    # 조치 완료 상태
    report_data["조치결과"] = "조치 완료"

    return report_data

# [U-14] 공통 환경 변수 파일 검사
def U14():
    report_data = {
        "이름": "U-14",
        "중요도": "상",
        "조치결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    chk_user = ["root", "user"]

    for user in chk_user:
        if user == "root":
            path = "/etc/"
            users = ["root"]
            file_list = ["environment", "bash.bashrc", "profile", "bashrc", "profile.d"]
        elif user == "user":
            users = subprocess.getoutput("ls /home").split()  # 사용자 목록
            file_list = [".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".kshrc", ".cshrc", ".login", ".exrc", ".netrc"]

        for u in users:
            if u != "root":
                path = f"/home/{u}/"
            for file in file_list:
                file_path = os.path.join(path, file)
                if os.path.exists(file_path):
                    # 파일 권한 확인 및 수정
                    output = subprocess.getoutput(f"ls -aldGQ {file_path}")
                    
                    # GID가 쓰기 권한이 있는지 확인 (GID가 쓰기 가능하면 조치)
                    if output[5] == 'w':
                        subprocess.run(f"chmod g-w {file_path}", shell=True)
                        print(f"GID 쓰기 권한 제거: {file_path}")

                    # 다른 사용자(Other)도 쓰기 권한이 있는지 확인 (다른 사용자가 쓰기 가능하면 조치)
                    if output[8] == 'w':
                        subprocess.run(f"chmod o-w {file_path}", shell=True)
                        print(f"다른 사용자 쓰기 권한 제거: {file_path}")

                    # 파일 소유자가 사용자 계정인지 확인 (소유자가 다르면 수정)
                    output = output.split("\"")
                    if output[0].find("root") == -1:  # 소유자가 root가 아니거나 다른 경우
                        subprocess.run(f"chown {u} {file_path}", shell=True)
                        print(f"파일 소유자 변경: {file_path} -> {u}")

    # 조치가 완료되었음을 보고
    report_data["조치결과"] = "조치완료"

    return report_data    

# [U-15] World Writeable 파일 검사
def U15():
    report_data = {
        "이름": "U-15",
        "중요도": "상",
        "조치결과": "",  
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    # 검사할 디렉토리 리스트
    directories = ["/home", "/tmp", "/etc", "/var"]
    
    # 쓰기 권한이 있는 파일을 찾고, 조치하기 위한 루프
    for directory in directories:
        output = subprocess.getoutput(f"find {directory} -type f -perm -2 2>/dev/null")

        if len(output) != 0:  # 쓰기 권한이 있는 파일이 있을 경우
            files = output.split("\n")
            
            for file in files:
                # 파일의 쓰기 권한을 제거 (소유자, 그룹 외 다른 사용자 권한 제거)
                subprocess.run(f"chmod o-w {file}", shell=True)
                print(f"'{file}' 의 쓰기 권한을 제거했습니다.")

            # 보안 조치 완료 후 조치 결과 업데이트
            report_data["조치결과"] = "조치완료"
        else:
            report_data["조치결과"] = "양호"

    return report_data

# [U-16] /dev 디렉터리 불필요 파일 검사
def U16():
    report_data = {
        "이름": "U-16",
        "중요도": "상",
        "조치결과": "",  
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    # /dev 디렉터리에서 불필요한 파일 검사
    output = subprocess.getoutput("find /dev -type f 2>/dev/null")
    unnecessary_files = output.splitlines()

    if unnecessary_files:
        # 불필요한 파일이 발견된 경우, 각 파일을 삭제하거나 이동
        for file in unnecessary_files:
            if "important" in file:  # 중요한 파일이 아닌 경우에만 삭제
                continue
            subprocess.run(f"rm -rf {file}", shell=True)
            print(f"'{file}' 파일을 삭제했습니다.")
            
        # 필요하다면 파일을 다른 디렉터리로 이동할 수 있습니다.
        # 예를 들어, 파일을 /var/tmp로 이동할 수 있습니다:
        # subprocess.run(f"mv {file} /var/tmp/", shell=True)

        # 조치 결과 업데이트
        report_data["조치결과"] = "조치완료"
    else:
        # 불필요한 파일이 없으면 안전
        report_data["조치결과"] = "양호"

    return report_data    

# [U-17] 'r' command 원격 접속 파일 검사
def U17():
    report_data = {
        "이름": "U-17",
        "중요도": "상",
        "조치결과": "",  
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    # 검사할 파일 리스트
    file_list = ["/etc/hosts.equiv", subprocess.getoutput("echo $HOME") + "/.rhosts"]
    flag = False

    # 각 파일에 대해 검사 및 조치 수행
    for file in file_list:
        if os.path.isfile(file):
            # 파일 소유자 확인 및 수정 (root 또는 현재 사용자로 변경)
            file_info = subprocess.getoutput("ls -l " + file + " 2>/dev/null").split()
            if file_info[2] != "root" and file_info[2] != getpass.getuser():
                subprocess.run(f"chown root {file}", shell=True)
                print(f"'{file}'의 소유자를 'root'로 변경했습니다.")
            
            # 파일 권한 확인 및 수정 (600으로 변경)
            if file_info[0] != "-rw-------":
                subprocess.run(f"chmod 600 {file}", shell=True)
                print(f"'{file}'의 권한을 600으로 변경했습니다.")

            # 파일 내용 검사 및 수정 (무분별한 '+' 문자 제거)
            file_content = subprocess.getoutput(f"cat {file} 2>/dev/null")
            if "+" in file_content:
                with open(file, 'r') as f:
                    lines = f.readlines()
                with open(file, 'w') as f:
                    for line in lines:
                        if "+" in line:
                            line = line.replace("+", "")  # '+' 문자 제거
                        f.write(line)
                print(f"'{file}'에서 '+' 문자를 제거했습니다.")

    # 조치 완료 상태로 설정
    report_data["조치결과"] = "조치완료"

    return report_data  

#[U-18] 접속 IP 및 포트 제한 파일 여부 검사
def U18():
    report_data = {
        "이름": "U-18",
        "중요도": "상",
        "조치결과": "",  
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    # 검사할 파일 리스트
    file_list = ['/etc/hosts.deny', '/etc/hosts.allow']
    flag = False

    # 파일 확인 및 조치 수행
    for file in file_list:
        if os.path.isfile(file):
            with open(file, mode='r', encoding='utf-8') as handle:
                content = handle.readlines()

            # 주석 제거 및 공백 제거 후 대문자로 변환
            filtered_content = [line.strip().upper() for line in content if not line.startswith("#")]
            output = ''.join(filtered_content).replace(" ", "")

            if file == "/etc/hosts.deny":
                # 'ALL:ALL' 문구가 없으면 추가
                if "ALL:ALL" not in output:
                    with open(file, 'a', encoding='utf-8') as handle:
                        handle.write("\nALL:ALL\n")  # 파일 끝에 'ALL:ALL' 추가
                    print(f"'{file}'에 'ALL:ALL'을 추가했습니다.")
            else:  # /etc/hosts.allow
                # 'ALL:ALL' 문구가 있으면 삭제
                if "ALL:ALL" in output:
                    new_content = [line for line in content if "ALL:ALL" not in line]
                    with open(file, 'w', encoding='utf-8') as handle:
                        handle.writelines(new_content)
                    print(f"'{file}'에서 'ALL:ALL'을 제거했습니다.")

        else:
            # 파일이 존재하지 않으면 새로 생성
            if file == '/etc/hosts.deny':
                with open(file, 'w', encoding='utf-8') as handle:
                    handle.write("ALL:ALL\n")
                print(f"'{file}' 파일이 없어서 새로 생성하고 'ALL:ALL'을 추가했습니다.")
            elif file == '/etc/hosts.allow':
                with open(file, 'w', encoding='utf-8') as handle:
                    handle.write("\n")
                print(f"'{file}' 파일이 없어서 새로 생성했습니다.")

    # 조치 완료 상태로 설정
    report_data["조치결과"] = "조치완료"

    return report_data 

#[U-19] finger 서비스 설치 여부 검사
def U19():
    # Debian 계열에서 finger 설치 여부 확인
    output = subprocess.getoutput("dpkg --get-selections | grep finger")
    output = output.split()

    if output == ['finger', 'install']:
        # Debian 계열에서는 apt 명령어로 제거
        subprocess.getoutput("apt remove finger -y")
        print("Debian 계열에서 'finger' 서비스를 제거했습니다.")

    else:
        # Redhat 계열에서 finger 서비스가 실행 중인지 확인
        output = subprocess.getoutput("finger")
        output = output.split()

        if output and output[0] == "Login" and output[1] == "Name" and output[2] == "Tty":
            # Redhat 계열에서는 yum 명령어로 제거
            subprocess.getoutput("yum remove finger -y")
            print("Redhat 계열에서 'finger' 서비스를 제거했습니다.")

    # 조치 완료 상태로 설정
    report_data["조치결과"] = "조치완료"

    return report_data 

#[U-20] Anonymous FTP 계정 비활성화 검사
def U20():
    report_data = {
        "이름": "U-20",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    flag = False
    ftp_user_found = False
    f_output = "[U-20] Anonmous FTP 계정 비활성화 검사\n"

    # FTP User Check
    with open("/etc/passwd", mode='r', encoding='utf-8') as handle:
        for line in handle:
            temp = line.upper().replace(" ", "")  # 대문자 변환 및 공백 제거
            if temp[0] != "#" and "FTP" in temp:  # FTP 계정 확인
                ftp_user_found = True
                f_output += "\t[알림] FTP 계정이 존재합니다.\n"
                report_data["조치내용"].append("FTP 계정이 존재함")
                break

    if not ftp_user_found:
        f_output += "\t[알림] FTP 계정이 존재하지 않습니다.\n"
        report_data["조치내용"].append("FTP 계정이 존재하지 않음")

    # FTP 설정 파일 확인
    ftp_configs = ["vsftpd", "vsftpd/vsftpd", "proftpd/proftpd"]
    for config in ftp_configs:
        config_path = f"/etc/{config}.conf"
        if os.path.isfile(config_path):  # 설정 파일이 존재하면
            f_output += f"\t[알림] {config.split('/')[0]} FTP 프로그램 설정 파일이 존재합니다.\n"
            report_data["조치내용"].append(f"{config.split('/')[0]} 설정 파일이 존재함")

            with open(config_path, mode='r', encoding='utf-8') as handle:
                for line in handle:
                    temp = line.upper().replace(" ", "")  # 대문자 변환 및 공백 제거
                    if temp[0] != "#":  # 주석 제외
                        if "VSFTPD" in config and "ANONYMOUS_ENABLE=YES" in temp:  # vsftpd.conf 확인
                            flag = True
                        elif "<ANONYMOUS~FTP>" in temp:  # proftpd.conf 확인
                            flag = True

            if flag:  # 익명 FTP 활성화된 경우
                f_output += "\t[경고] /etc/" + config + ".conf : anonymous 계정 접속이 활성화되어 있습니다.\n"
                f_output += "\t[검사 결과] 보안 조치가 필요합니다.\n"
                report_data["조치결과"] = "취약"
                report_data["조치내용"].append(f"/etc/{config}.conf : anonymous 접속 활성화됨")
                flag = False
            else:
                f_output += "\t[검사 결과] 안전합니다.\n"
                report_data["조치결과"] = "양호"
                report_data["조치내용"].append(f"/etc/{config}.conf : anonymous 접속 비활성화됨")

    # FTP 계정 존재 & 설정 파일 없을 경우 보안 조치 필요
    if "[검사 결과]" not in f_output:
        f_output += "\t[알림] FTP 프로그램 설정 파일이 존재하지 않습니다.\n"
        if ftp_user_found:
            f_output += "\t[검사 결과] 보안 조치가 필요합니다.\n"
            report_data["조치결과"] = "취약"
            report_data["조치내용"].append("FTP 계정이 존재하나 설정 파일이 없음")
        else:
            f_output += "\t[검사 결과] 안전합니다.\n"
            report_data["조치결과"] = "양호"

    return report_data

#[U-21] 계열 서비스 비활성화 검사
def U21():
    report_data = {
        "이름": "U-21",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    f_output = "[U-21] r 계열 서비스 비활성화 검사\n"
    flag = False
    services = ["rlogin", "rsh", "rexec"]

    # r 계열 서비스 확인
    for service in services:
        path = f"/etc/xinetd.d/{service}"

        if os.path.isfile(path):
            with open(path, mode='r', encoding='utf-8') as handle:
                temp = handle.read()

            temp = temp.replace(" ", "").upper()  # 공백 제거 및 대문자로 변환
            if "DISABLE=YES" not in temp:  # disable 설정이 없는 경우
                f_output += f"\t[경고] {path} : r계열 서비스가 비활성화 되어 있지 않습니다.\n"
                report_data["조치내용"].append(f"{service} 서비스가 비활성화 되어 있지 않음")
                flag = True

    # 결과 처리
    if flag:
        report_data["조치결과"] = "취약"
    else:
        report_data["조치결과"] = "양호"
        report_data["조치내용"].append("모든 r 계열 서비스가 비활성화됨")

    return report_data

#[U-22] Cron 관련 설정 파일 점검
def U22():
    report_data = {
        "이름": "U-22",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    f_output = "[U-22] Cron 관련 설정 파일 점검\n"
    flag = False
    files = ["/etc/cron.allow", "/etc/cron.deny"]

    for file in files:
        if os.path.isfile(file):
            file_info = subprocess.getoutput(f"ls -l {file}").split()
            permissions = file_info[0]
            owner = file_info[2]

            if permissions not in ["-rw-r-----", "-rw-------"]:
                f_output += f"\t[경고] {file} : 파일의 권한 값({permissions})이 취약합니다.\n"
                report_data["조치내용"].append(f"{file} 파일의 권한이 {permissions}으로 취약")
                flag = True

            if owner != "root":
                f_output += f"\t[경고] {file} : 파일의 소유자가 root 계정이 아닙니다.\n"
                report_data["조치내용"].append(f"{file} 파일의 소유자가 {owner}으로 root가 아님")
                flag = True

    # /etc/cron.allow 파일이 없고 /etc/cron.deny 파일만 있는 경우
    if os.path.isfile(files[1]) and not os.path.isfile(files[0]):
        f_output += f"\t[경고] /etc/cron.deny : 해당 파일만 존재하면 취약합니다.\n"
        report_data["조치내용"].append("/etc/cron.deny 파일만 존재하여 취약")
        flag = True

    # 결과 처리
    if flag:
        report_data["조치결과"] = "취약"
    else:
        report_data["조치결과"] = "양호"
        report_data["조치내용"].append("모든 Cron 설정 파일이 안전함")

    return report_data

#[U-23] DoS 공격에 취약한 서비스 비활성화 검사
def U23():
    report_data = {
        "이름": "U-23",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    f_output = "[U-23] DoS 공격에 취약한 서비스 비활성화 검사\n"
    flag = False
    inetd_path = "/etc/inetd.conf"
    vulnerable_services = [
        "echo", "echo-udp", "discard", "discard-udp", 
        "daytime", "daytime-udp", "chargen", "chargen-udp", 
        "ntp", "ntp-udp", "snmp", "snmp-udp"
    ]

    # /etc/inetd.conf Scan
    if os.path.isfile(inetd_path):
        with open(inetd_path, mode="r", encoding="utf-8") as handle:
            for line in handle:
                stripped_line = line.replace(" ", "").upper()
                if stripped_line and not stripped_line.startswith("#"):
                    for service in vulnerable_services:
                        if service.upper() in stripped_line:
                            report_data["조치내용"].append(f"{inetd_path} : {service} 서비스가 활성화 되어 있습니다.")
                            flag = True

    # /etc/xinetd.d/ Scan
    xinetd_path = "/etc/xinetd.d/"
    for service in vulnerable_services:
        service_path = os.path.join(xinetd_path, service)
        if os.path.isfile(service_path):
            with open(service_path, mode="r", encoding="utf-8") as handle:
                data = handle.read().replace(" ", "").replace("\t", "").upper()
                if data.count("{") != data.count("DISABLE=YES"):
                    report_data["조치내용"].append(f"{service_path} : {service} 서비스가 활성화 되어 있습니다.")
                    flag = True

    # 결과 처리
    if flag:
        report_data["조치결과"] = "취약"
    else:
        report_data["조치결과"] = "양호"
        report_data["조치내용"].append("모든 서비스가 비활성화 되어 안전함")

    return report_data    

#[U-24] NFS 서비스 비활성화 검사
def U24():
    report_data = {
        "이름": "U-24",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    f_output = "[U-24] NFS 서비스 비활성화 검사\n"
    flag = False

    # NFS 서비스 체크
    temp = subprocess.getoutput("ps -ef | egrep 'nfsd|statd|lockd'")
    if "[nfsd]" in temp or "[statd]" in temp or "[lockd]" in temp:
        report_data["조치내용"].append("NFS 서비스가 활성화 되어 있습니다.")
        report_data["조치내용"].append("NFS 서비스는 취약할 수 있으므로, 다른 파일 공유 서비스 이용을 권장합니다.")
        flag = True

    # 결과 처리
    if flag:
        report_data["조치결과"] = "취약"
    else:
        report_data["조치결과"] = "양호"
        report_data["조치내용"].append("NFS 서비스가 비활성화되어 안전합니다.")

    return report_data

#[U-25] NFS 서비스 접근 통제 검사
def U25():
    report_data = {
        "이름": "U-25",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    path = "/etc/exports"
    flag = False

    if os.path.isfile(path):
        # 파일 권한 및 소유자 체크
        file_info = subprocess.getoutput("ls -al " + path).split()
        
        # 파일이 다른 사용자에게 수정 가능 여부 확인
        if file_info[0][8] != "-":
            report_data["조치내용"].append(f"{path}: 해당 파일을 다른 사용자가 수정할 수 있습니다.")
            flag = True

        # 소유자 확인
        if file_info[2] != "root":
            report_data["조치내용"].append(f"{path}: 해당 파일의 소유자가 root가 아닙니다.")
            flag = True

        # 설정 파일 내용 체크
        with open(path, mode="r", encoding="utf-8") as handle:
            data = ""
            for line in handle:
                cleaned_line = line.replace(" ", "").replace("\t", "").replace("\n", "").upper()
                if cleaned_line and cleaned_line[0] != "#":
                    data += cleaned_line

            if "*" in data:
                report_data["조치내용"].append(f"{path}: NFS 서버 접근 설정이 모두(everyone)로 되어 있습니다. '*' 사용은 금지해야 합니다.")
                flag = True

    # 결과 처리
    if flag:
        report_data["조치결과"] = "취약"
    else:
        report_data["조치결과"] = "양호"
        report_data["조치내용"].append(f"{path}: 설정 파일 및 권한이 안전합니다.")

    return report_data

#[U-26] automountd 설치 검사
def U26():
    report_data = {
        "이름": "U-26",
        "중요도": "상",
        "조치결과": "",
        "조치내용": [],
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    flag = False

    # autofs 서비스 확인
    temp = subprocess.getoutput("ps -ef | grep autofs")

    if "autofs.pid" in temp:
        report_data["조치내용"].append("automountd(autofs) 서비스가 활성화 되어 있습니다.")
        flag = True

    # 결과 처리
    if flag:
        report_data["조치결과"] = "취약"
    else:
        report_data["조치결과"] = "양호"
        report_data["조치내용"].append("automountd(autofs) 서비스가 비활성화 되어 있습니다.")

    return report_data   

#[U-27] 불필요한 RPC 서비스 검사
def U27():
    report_data = {
        "이름": "U-27",
        "중요도": "상",
        "진단결과": "",
        "server": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "담당자": "김가현"
    }

    flag = False
    rpc_services = "rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd"
    rpc_services = rpc_services.split()

    # /etc/inetd.conf 파일 검사 및 자동 조치
    inetd_path = "/etc/inetd.conf"
    if os.path.isfile(inetd_path):
        with open(inetd_path, mode="r", encoding="utf-8") as handle:
            lines = handle.readlines()

        with open(inetd_path, mode="w", encoding="utf-8") as handle:
            for line in lines:
                for service in rpc_services:
                    if service in line and not line.startswith("#"):
                        flag = True
                        line = "#" + line  # 주석 처리
                handle.write(line)

    # /etc/xinetd.d/ 디렉터리 검사 및 자동 조치
    xinetd_path = "/etc/xinetd.d/"
    for service in rpc_services:
        service_path = os.path.join(xinetd_path, service)
        if os.path.isfile(service_path):
            with open(service_path, mode="r", encoding="utf-8") as handle:
                lines = handle.readlines()

            with open(service_path, mode="w", encoding="utf-8") as handle:
                for line in lines:
                    if "disable" in line.lower():
                        if "yes" not in line.lower():
                            flag = True
                            line = "disable = yes\n"  # disable 설정 추가
                    handle.write(line)

    # 결과 설정
    if flag:
        report_data["진단결과"] = "취약"
    else:
        report_data["진단결과"] = "양호"

    return report_data         

# Main 함수
def main():
    print("조치를 시작합니다..")

# 각 점검 결과를 final_report에 추가
    final_report.append(U01())
    final_report.append(U04())
    final_report.append(U05())
    final_report.append(U06())
    final_report.append(U07())
    final_report.append(U08())
    final_report.append(U09())
    final_report.append(U10())
    final_report.append(U11())
    final_report.append(U12())
    final_report.append(U13())
    final_report.append(U14())
    final_report.append(U15())
    final_report.append(U16())
    final_report.append(U17())
    final_report.append(U18())
    final_report.append(U19())
    final_report.append(U20())
    final_report.append(U21())
    final_report.append(U22())
    final_report.append(U23())
    final_report.append(U24())
    final_report.append(U25())
    final_report.append(U26())
    final_report.append(U27())

    

# JSON 파일에 결과 저장
    with open('action_results.json', 'w') as json_file:
        json.dump(final_report, json_file, ensure_ascii=False, indent=4)
        print("결과가 action_results.json 파일에 저장되었습니다.")

if __name__ == "__main__":
    main()
