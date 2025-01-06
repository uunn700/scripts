import json 
from os import path
import subprocess
import os 
from os import stat, path
import printModule as pm
import getpass

import logstash_loader

# U-01: root 계정 원격 접속 제한 
def U01():
    report_data = {
        "항목코드": "U-01",
        "중요도": "상",
        "결과": "", 
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"  
    }    

    isSafeLogin = True
    tocheck = 'pam_securetty.so'
    
    # /etc/pam.d/login 파일 검사
    try:
        with open('/etc/pam.d/login', 'r') as f:
            for line in f:
                if tocheck in line:
                    index = line.find(tocheck)
                    if '#' not in line[:index]:
                        isSafeLogin = True
                    else:
                        isSafeLogin = False
        if not isSafeLogin:
            report_data["결과"] = "취약"
    except FileNotFoundError:
        report_data["결과"] = "취약"

    # /etc/securetty 파일 검사
    isSafeSecuretty = True
    if os.path.isfile('/etc/securetty'):
        tocheck = 'pts'
        with open('/etc/securetty', 'r') as f:
            for line in f:
                if tocheck in line:
                    index = line.find(tocheck)
                    if '#' not in line[:index]:
                        isSafeSecuretty = False
        if not isSafeSecuretty:
            report_data["결과"] = "취약"

    # /etc/ssh/sshd_config 파일 검사
    isSafeSshd = True
    if os.path.isfile('/etc/ssh/sshd_config'):
        tocheck = 'PermitRootLogin'
        with open('/etc/ssh/sshd_config', 'r') as f:
            for line in f:
                if tocheck in line:
                    index = line.find(tocheck)
                    if '#' not in line[:index]:
                        isSafeSshd = False
        if not isSafeSshd:
            report_data["결과"] = "취약"

    # 모든 검사가 양호할 경우 진단결과 수정
    if isSafeLogin and isSafeSecuretty and isSafeSshd:
        report_data["결과"] = "양호"  # 모든 검사에서 문제가 없으면 '양호'

    return report_data

# U-02: 패스워드 복잡성 설정
def U02():
    report_data = {
        "항목코드": "U-02",
        "중요도": "상",
        "결과": "",  
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",  
        "점검자": "김가현"  
    }

    isSafe = True
    output = subprocess.getoutput('dpkg -l | grep libpam-pwquality')
    if not ('libpam-pwquality' in output):
        report_data["결과"] = "취약"
        isSafe = False
    else:
        # pam_pwquality 설정 확인
        tocheck = 'password requisite pam_pwquality.so'
        tocheck = ''.join(tocheck.split())
        try:
            with open('/etc/pam.d/common-password', 'r') as f:
                for line in f:
                    line = ''.join(line.split())  # 공백 제거
                    if tocheck in line:
                        # 주석인지 확인
                        if '#' in line:
                            continue

                        # minlen 설정 확인
                        index = line.find('minlen=')
                        if index < 0:
                            report_data["결과"] = "취약"
                            isSafe = False
                        else:
                            index += len('minlen=')
                            minlen = ''
                            while index < len(line) and line[index].isdigit():
                                minlen += line[index]
                                index += 1
                            if int(minlen) < 8:
                                report_data["결과"] = "취약"
                                isSafe = False
                        
                        # lcredit 설정 확인
                        if 'lcredit=-1' not in line:
                            report_data["결과"] = "취약"
                            isSafe = False

                        # ucredit 설정 확인
                        if 'ucredit=-1' not in line:
                            report_data["결과"] = "취약"
                            isSafe = False

                        # dcredit 설정 확인
                        if 'dcredit=-1' not in line:
                            report_data["결과"] = "취약"
                            isSafe = False

                        # ocredit 설정 확인
                        if 'ocredit=-1' not in line:
                            report_data["결과"] = "취약"
                            isSafe = False

            if isSafe:
                report_data["결과"] = "양호"  # 모든 조건이 양호하면 '양호'로 설정

        except FileNotFoundError:
            report_data["결과"] = "취약"
            
    return report_data

# U-03: 계정 잠금 임계값 설정
def U03():
    report_data = {
        "항목코드": "U-03",
        "중요도": "상",
        "결과": "",  
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",  
        "점검자": "김가현"  
    }

    isSafe = False
    isSet = False
    tocheck = 'auth required pam_tally2.so'
    tocheck = ''.join(tocheck.split())

    try:
        with open('/etc/pam.d/common-auth', 'r') as f:
            for line in f:
                line = ''.join(line.split())  # 공백 제거
                if tocheck in line:
                    # 주석인지 확인
                    if '#' in line:
                        continue

                    index = line.find('deny=')
                    if index < 0:
                        continue
                    index += len('deny=')
                    limit = ''
                    while index < len(line) and line[index] > '0' and line[index] < '9':
                        limit += line[index]
                        index += 1
                    if int(limit) > 5:
                        report_data["결과"] = "취약"
                        isSet = True
                    else:
                        isSafe = True
                        report_data["결과"] = "양호"
                        isSet = True
    except FileNotFoundError:
        report_data["결과"] = "취약"

    if not isSet:
        report_data["결과"] = "취약"

    # 취약하지 않으면 취약부분 삭제
    if isSafe:
        report_data["결과"] = "양호"

    return report_data	

# U-04: 패스워드 파일 보호
def U04():
    report_data = {
        "항목코드": "U-04",
        "중요도": "상",
        "결과": "", 
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # /etc/shadow 파일 존재 여부 확인
    isShadow = os.path.isfile("/etc/shadow")
    if not isShadow:
        report_data["결과"] = "취약"

    # 패스워드 암호화 확인
    isCrypto = False
    if isShadow:
        try:
            with open('/etc/passwd', 'r') as f:
                line = f.readline().split(':')
                if line[1] == 'x':
                    isCrypto = True
                else:
                    report_data["결과"] = "취약"
        except FileNotFoundError:
            report_data["결과"] = "취약"

    # 모든 조건이 양호할 경우 결과를 "양호"로 설정
    if isShadow and isCrypto:
        report_data["결과"] = "양호"

    return report_data

# U-44: UID가 0인 사용자 확인
def U44():
    report_data = {
        "항목코드": "U-44",
        "중요도": "중",
        "결과": "", 
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # /etc/passwd 파일 확인
    try:
        with open('/etc/passwd', 'r') as f:
            isSafe = True
            for line in f:
                splitLine = line.split(':')
                name = splitLine[0]
                uid = splitLine[2]
                if (name != 'root') and (uid == '0'):
                    isSafe = False
                    report_data["결과"] = "취약"
                    
            if isSafe:
                report_data["결과"] = "양호"
    except FileNotFoundError:
        report_data["결과"] = "취약"

    return report_data              

# U-45: su 명령어 사용 제한 점검
def U45():
    report_data = {
        "항목코드": "U-45",
        "중요도": "하",
        "결과": "",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # /etc/pam.d/su 파일 검사
    try:
        with open('/etc/pam.d/su', 'r') as f:
            isSafe = False
            tocheck = 'auth required pam_wheel.so'
            tocheck = ''.join(tocheck.split())
            for line in f:
                line = ''.join(line.split())
                if tocheck in line and '#' not in line:
                    isSafe = True
                    break

            if isSafe:
                report_data["결과"] = "양호"
            else:
                report_data["결과"] = "취약"
    except FileNotFoundError:
        report_data["결과"] = "취약"

    return report_data

# U-46: 패스워드 최소 길이 설정
def U46():
    report_data = {
        "항목코드": "U-46",
        "중요도": "중",
        "결과": "",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    isSet = False

    try:
        with open('/etc/login.defs', 'r') as f:
            for line in f:
                line = ''.join(line.split())
                index = line.find('PASS_MIN_LEN')
                if index >= 0:
                    # 주석인지 확인
                    if '#' in line[0:index]:
                        continue

                    passLen = line[index + len('PASS_MIN_LEN'):].strip()
                    if passLen == '':
                        continue
                    elif int(passLen) < 8:
                        report_data["결과"] = "취약"
                        isSet = True
                    else:
                        report_data["결과"] = "양호"
                        isSet = True
    except FileNotFoundError:
        report_data["결과"] = "취약"

    if not isSet:
        report_data["결과"] = "취약"

    return report_data

# U-47: 패스워드 최대 사용기간 설정
def U47():
    report_data = {
        "항목코드": "U-47",
        "중요도": "중",
        "결과": "",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    isSet = False

    try:
        with open('/etc/login.defs', 'r') as f:
            for line in f:
                line = ''.join(line.split())
                index = line.find('PASS_MAX_DAYS')
                if index >= 0:
                    # 주석인지 확인
                    if '#' in line[0:index]:
                        continue

                    days = line[index + len('PASS_MAX_DAYS'):].strip()
                    if days == '':
                        continue
                    elif int(days) > 90:
                        report_data["결과"] = "취약"
                        isSet = True
                    else:
                        report_data["결과"] = "양호"
                        isSet = True
    except FileNotFoundError:
        report_data["결과"] = "취약"

    if not isSet:
        report_data["결과"] = "취약"

    return report_data

# U-48: 패스워드 최소 사용기간 설정
def U48():
    report_data = {
        "항목코드": "U-48",
        "중요도": "중",
        "결과": "",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    isSet = False

    try:
        with open('/etc/login.defs', 'r') as f:
            for line in f:
                line = ''.join(line.split())
                index = line.find('PASS_MIN_DAYS')
                if index >= 0:
                    # 주석인지 확인
                    if '#' in line[0:index]:
                        continue

                    days = line[index + len('PASS_MIN_DAYS'):].strip()
                    if days == '':
                        continue
                    elif int(days) < 1:
                        report_data["결과"] = "취약"
                        isSet = True
                    else:
                        report_data["결과"] = "양호"
                        isSet = True
    except FileNotFoundError:
        report_data["결과"] = "취약"

    if not isSet:
        report_data["결과"] = "취약"

    return report_data
    
# U-49: 불필요한 계정 제거
def U49():
    report_data = {
        "항목코드": "U-49",
        "중요도": "하",
        "결과": "수동 점검 필요",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
          # 점검이 수동으로 필요함을 나타냄
    }

    return report_data  
   
# U-50: 관리자 그룹에 최소한의 계정 포함
def U50():
    report_data = {
        "항목코드": "U-50",
        "중요도": "하",
        "결과": "",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    isSafe = True

    try:
        with open('/etc/group', 'r') as f:
            for line in f:
                splitLine = line.split(':')
                group = splitLine[0]

                # KISA 매뉴얼에는 root 그룹만 검사
                if group == 'root':
                    users = splitLine[3].split(',')
                    users = [user for user in users if user]  # 빈 문자열 제거
                    numOfUsers = len(users)

                    if 'root' in users:
                        numOfUsers -= 1

                    if numOfUsers > 0:
                        report_data["결과"] = "취약"
                        isSafe = False

                elif group == 'sudo':
                    users = splitLine[3].split(',')
                    users = [user for user in users if user]  # 빈 문자열 제거
                    numOfUsers = len(users)

                    if 'sudo' in users:
                        numOfUsers -= 1

                    if numOfUsers > 0:
                        report_data["결과"] = "취약"
                        isSafe = False

    except FileNotFoundError:
        report_data["결과"] = "취약"

    if isSafe:
        report_data["결과"] = "양호"

    return report_data
    
# U-51: 계정이 존재하지 않는 GID 금지
def U51():
    report_data = {
        "항목코드": "U-51",
        "중요도": "하",
        "결과": "수동 점검 필요",
        "분류": "계정관리",  # 기본값을 주의로 설정
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }
    
    # 시스템 관리자가 수동으로 점검하도록 안내
    # 파일을 열고 검토를 위한 메시지를 출력합니다.
    with open('/etc/group', 'r') as f:
        group_data = f.readlines()
        
    with open('/etc/passwd', 'r') as f:
        passwd_data = f.readlines()

    # 여기에서 group_data와 passwd_data를 비교하여 불필요한 그룹을 점검
    # 실제 불필요한 그룹 확인 로직을 추가하면 됩니다.
    # 예를 들어, 존재하지 않는 GID를 찾는 로직 등을 추가할 수 있습니다.

    # 해당 내용은 수동 점검을 필요로 하므로 "주의"로 설정
    report_data["결과"] = "수동 점검 필요"

    return report_data  
    
# U-52: 동일한 UID 금지
def U52():
    report_data = {
        "항목코드": "U-52",
        "중요도": "중",
        "결과": "",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    existUID = set()  # 중복 UID를 확인하기 위해 set 사용
    isSafe = True

    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                splitLine = line.split(':')
                uid = splitLine[2]

                if uid in existUID:
                    isSafe = False
                    report_data["결과"] = "취약"
                    break  # 중복 발견 시 더 이상의 검사 중지

                existUID.add(uid)

    except FileNotFoundError:
        report_data["결과"] = "취약"

    if isSafe and report_data["결과"] == "":
        report_data["결과"] = "양호"

    return report_data

# U-53: 사용자 shell 점검
def U53():
    report_data = {
        "항목코드": "U-53",
        "중요도": "하",
        "결과": "",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    names = [
        'daemon',
        'bin',
        'sys',
        'adm',
        'games',
        'listen',
        'nobody',
        'nobody4',
        'noaccess',
        'diag',
        'operator',
        'gopher'
    ]

    isNologin = True

    try:
        with open('/etc/passwd', 'r') as f:
            for line in f:
                splitLine = line.split(':')
                name = splitLine[0]
                shell = splitLine[6]

                if name in names:
                    if (shell.find('/usr/sbin/nologin') < 0) and \
                       (shell.find('/bin/false') < 0) and \
                       (shell.find('/sbin/nologin') < 0):
                        isNologin = False
                        report_data["결과"] = "취약"
                        break  # 취약점 발견 시 더 이상의 검사 중지

        if isNologin and report_data["결과"] == "":
            report_data["결과"] = "양호"

    except FileNotFoundError:
        report_data["결과"] = "취약"

    return report_data
    
# U-54: Session Timeout 설정
def U54():
    report_data = {
        "항목코드": "U-54",
        "중요도": "하",
        "결과": "",
        "분류": "계정관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # check bash
    try:
        shell = subprocess.check_output('echo $SHELL', shell=True).decode('utf-8').strip()
        if 'bash' not in shell:
            report_data["결과"] = "양호"
            return report_data
    except subprocess.CalledProcessError:
        report_data["결과"] = "취약"

    try:
        echoRst = subprocess.check_output('echo $TMOUT', shell=True).decode('utf-8').strip()
        time = echoRst

        if time == '':
            report_data["결과"] = "취약"
        elif int(time) > 600:
            report_data["결과"] = "취약"
        else:
            report_data["결과"] = "양호"

    except subprocess.CalledProcessError:
        report_data["결과"] = "취약"

    return report_data


# U-05: 2.1 root 홈, 패스 디렉터리 권한 및 패스 설정
def U05():
    report_data = {
        "항목코드": "U-05",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # 현재 계정의 PATH 환경 변수 검사
    envList = subprocess.check_output('echo $PATH', shell=True).decode().strip()
    isNotDot = True
    isNotColon = True

    if '.' in envList:
        report_data["결과"] = "취약"
        isNotDot = False

    if '::' in envList:
        report_data["결과"] = "취약"
        isNotColon = False

    # 모든 검사가 양호할 경우 진단결과 수정
    if isNotDot and isNotColon:
        report_data["결과"] = "양호"  # 모든 검사에서 문제가 없으면 '양호'
        
    return report_data

# U-06: 파일 및 디렉터리 소유자 설정
def U06():
    report_data = {
        "항목코드": "U-06",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # 모든 파일 검사 (임시로 '/etc' 디렉터리만 검사)
    try:
        result = subprocess.check_output('find / -nouser', shell=True).decode().strip()
        if result:
            report_data["결과"] = "취약"
        else:
            report_data["결과"] = "양호"
    except subprocess.CalledProcessError:
        report_data["결과"] = "취약"
        
    return report_data

# U-07: /etc/passwd 파일 소유자 및 권한 설정
def U07():
    report_data = {
        "항목코드": "U-07",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # /etc/passwd 파일 소유자 및 권한 검사
    status = os.stat('/etc/passwd')

    owner = status.st_uid
    if owner == 0:
        report_data["결과"] = "양호"
    else:
        report_data["결과"] = "취약"

    perm = int(oct(status.st_mode)[-3:])
    if perm <= 644:
        if report_data["결과"] != "취약":
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "취약"

    return report_data
    
# U-08: /etc/shadow 파일 소유자 및 권한 설정
def U08():
    report_data = {
        "항목코드": "U-08",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # /etc/shadow 파일 존재 여부 확인
    isShadow = path.isfile('/etc/shadow')
    if not isShadow:
        report_data["결과"] = "취약"
        # 결과를 JSON 파일로 저장
        with open('/home/kisia/scripts/check_results.json', 'w') as json_file:
            json.dump(report_data, json_file, ensure_ascii=False, indent=4)
        return report_data

    status = stat('/etc/shadow')

    # 소유자 검사
    owner = status.st_uid
    if owner == 0:
        report_data["결과"] = "양호"  # 소유자가 root인 경우 '양호'
    else:
        report_data["결과"] = "취약"

    # 권한 검사
    perm = int(oct(status.st_mode)[-3:])
    if perm != 400:
        report_data["결과"] = "취약"

    return report_data    

# U-09: /etc/hosts 파일 소유자 및 권한 설정
def U09():
    report_data = {
        "항목코드": "U-09",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    status = stat('/etc/hosts')

    # 소유자 검사
    owner = status.st_uid
    if owner == 0:
        report_data["결과"] = "양호"  # 소유자가 root인 경우 '양호'
    else:
        report_data["결과"] = "취약"

    # 권한 검사
    perm = int(oct(status.st_mode)[-3:])
    if perm != 600:
        report_data["결과"] = "취약"

    return report_data
        
# U-10: /etc/(x)inetd.conf 파일 소유자 및 권한 설정
def U10():
    report_data = {
        "항목코드": "U-10",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # 확인할 파일 경로 변수
    filename = None

    # /etc/inetd.conf 파일 존재 여부 확인
    isInetd = path.isfile('/etc/inetd.conf')
    if isInetd:
        filename = '/etc/inetd.conf'
    
    # /etc/xinetd.conf 파일 존재 여부 확인
    isXinetd = path.isfile('/etc/xinetd.conf')
    if isXinetd:
        filename = '/etc/xinetd.conf'

    # 둘 다 없는 경우 처리
    if not isInetd and not isXinetd:
        report_data["결과"] = "취약"
        return report_data

    # 파일 상태 확인
    status = stat(filename)

    # 소유자 확인
    owner = status.st_uid
    if owner != 0:
        report_data["결과"] = "취약"

    # 권한 확인
    perm = int(oct(status.st_mode)[-3:])
    if perm != 600:
        report_data["결과"] = "취약"

    # 최종 상태 확인
    if report_data["결과"] == "":
        report_data["결과"] = "양호"

    return report_data
    
# U-11: /etc/(r)syslog.conf 파일 소유자 및 권한 설정
def U11():
    report_data = {
        "항목코드": "U-11",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    filename = ''

    # /etc/syslog.conf 파일 존재 여부 확인
    isSyslog = path.isfile('/etc/syslog.conf')
    if isSyslog:
        filename = '/etc/syslog.conf'
    else:
        report_data["결과"] = "취약"

    # /etc/rsyslog.conf 파일 존재 여부 확인
    isRsyslog = path.isfile('/etc/rsyslog.conf')
    if isRsyslog:
        filename = '/etc/rsyslog.conf'
    else:
        report_data["결과"] = "취약"

    # 두 파일 모두 없는 경우
    if not isSyslog and not isRsyslog:
        return report_data

    # 파일 상태 확인
    status = stat(filename)

    # 소유자 확인
    owner = status.st_uid
    if owner != 0:
        report_data["결과"] = "취약"

    # 권한 확인
    perm = int(oct(status.st_mode)[-3:])
    if perm != 644:
        report_data["결과"] = "취약"

    # 최종 상태 확인
    if report_data["결과"] == "":
        report_data["결과"] = "양호"

    return report_data     
    
# U-12: /etc/services 파일 소유자 및 권한 설정
def U12():
    report_data = {
        "항목코드": "U-12",
        "중요도": "상",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    status = stat('/etc/services')

    owner = status.st_uid
    if owner != 0:
        report_data["결과"] = "취약"

    perm = int(oct(status.st_mode)[-3:])
    if perm > 644:
        report_data["결과"] = "취약"

    if report_data["결과"] == "":
        report_data["결과"] = "양호"

    return report_data


# U-13: SUID, SGID, sticky bit 설정 및 권한 설정
def U13():
    report_data = {
        "항목코드": "U-13",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    SUID = 0o4000
    SGID = 0o2000

    isSafe = True

    # 불필요한 SUID/SGID 파일 목록
    files = [
        '/sbin/dump', '/sbin/restore', '/sbin/unix_chkpwd', '/usr/bin/at',
        '/usr/bin/lpq', '/usr/bin/lpq-lpd', '/usr/bin/lprm', '/usr/bin/lprm-lpd',
        '/usr/bin/newgrp', '/usr/sbin/lpc', '/usr/sbin/lpc-lpd', '/usr/sbin/traceroute'
    ]

    for file in files:
        if not os.path.isfile(file):
            continue

        status = os.stat(file)
        perm = int(oct(status.st_mode)[-4:])

        if perm & SUID:
            isSafe = False
        if perm & SGID:
            isSafe = False

    # 모든 검사가 양호할 경우 진단결과 수정
    if isSafe:
        report_data["결과"] = "양호"
    else:
        report_data["결과"] = "취약"

    return report_data


# U-14: 공통 환경 변수 파일 검사
def U14():
    report_data = {
        "항목코드": "U-14",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    chk_user = ["root", "user"]
    flag = False

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
                    flag = True

    if flag:
        report_data["결과"] = "양호"
    else:
        report_data["결과"] = "취약"

    return report_data


# U-15: 스크립트 파일 소유자 및 권한 설정
def U15():
    report_data = {
        "항목코드": "U-15",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    files = [
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"
    ]

    isSafe = True
    for directory in files:
        for dirpath, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                if os.access(filepath, os.X_OK):  # 실행 권한 확인
                    status = os.stat(filepath)
                    owner = status.st_uid
                    if owner != 0:  # 소유자가 root가 아니면
                        isSafe = False

    if isSafe:
        report_data["결과"] = "양호"
    else:
        report_data["결과"] = "취약"

    return report_data

# U-16: /dev 디렉터리 불필요한 파일 검사
def U16():
    report_data = {
        "항목코드": "U-16",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # /dev 디렉터리에서 불필요한 파일 검사
    output = subprocess.getoutput("find /dev -type f 2>/dev/null")
    unnecessary_files = output.splitlines()

    # 불필요한 파일이 발견된 경우
    if unnecessary_files:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data


# U-17: 'r' command 원격 접속 파일 검사
def U17():
    report_data = {
        "항목코드": "U-17",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # 검사할 파일 리스트
    file_list = ["/etc/hosts.equiv", subprocess.getoutput("echo $HOME") + "/.rhosts"]
    flag = False

    # 각 파일에 대해 검사 수행
    for file in file_list:
        if os.path.isfile(file):
            output = subprocess.getoutput("ls -l " + file + " 2>/dev/null").split()
            
            # 파일 소유자 검사
            if output[2] != "root" and output[2] != getpass.getuser():
                flag = True

            # 파일 권한 검사
            if output[0] != "-rw-------":
                flag = True

            # 파일 내용 검사 (무분별 허용 "+" 여부 확인)
            file_content = subprocess.getoutput(f"cat {file} 2>/dev/null")
            if "+" in file_content:
                flag = True

    # 취약점이 발견된 경우
    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data


# U-18: 접속 IP 및 포트 제한 파일 여부 검사
def U18():
    report_data = {
        "항목코드": "U-18",
        "중요도": "상",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # 검사할 파일 리스트
    file_list = ['/etc/hosts.deny', '/etc/hosts.allow']
    flag = False

    # 각 파일에 대해 검사 수행
    for file in file_list:
        if os.path.isfile(file):
            with open(file, mode='r', encoding='utf-8') as handle:
                content = handle.readlines()

            # 주석 제거 및 공백 제거 후 대문자로 변환
            filtered_content = [line.strip().upper() for line in content if not line.startswith("#")]
            output = ''.join(filtered_content).replace(" ", "")

            if file == "/etc/hosts.deny":
                if "ALL:ALL" not in output:
                    flag = True
            else:  # hosts.allow
                if "ALL:ALL" in output:
                    flag = True
        else:
            flag = True

    # 취약점이 발견된 경우
    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data
    
# U-55: /etc/hosts.lpd 파일 검사
def U55():
    report_data = {
        "항목코드": "U-55",
        "중요도": "하",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # /etc/hosts.lpd 파일 존재 여부 확인
    if os.path.isfile("/etc/hosts.lpd"):
        report_data["결과"] = "양호"  # 기본적으로 양호로 설정
        temp = subprocess.getoutput("ls -l /etc/hosts.lpd").split()

        # 파일 권한 검사
        if temp[0] != "-rw-------":
            report_data["결과"] = "취약"
        
        # 파일 소유자 검사
        if temp[2] != "root":
            report_data["결과"] = "취약"
    else:
        report_data["결과"] = "취약"

    return report_data


# U-56: NIS 서비스 활성 여부 검사
def U56():
    report_data = {
        "항목코드": "U-56",
        "중요도": "중",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False

    # NIS 서비스 활성 여부 확인
    services = subprocess.getoutput("ps -ef | egrep 'ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated' | grep -v grep")
    if services:
        flag = True
        report_data["결과"] = "취약"

    if not flag:
        report_data["결과"] = "양호"

    return report_data


# U-57: UMASK 값 검사
def U57():
    report_data = {
        "항목코드": "U-57",
        "중요도": "중",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False

    # 검사할 파일 목록
    file_list = [
        "/etc/profile",
        "/etc/default",
        "/etc/bashrc",
        "/etc/bash.bashrc",
        "/etc/login.defs",
        "/etc/pam.d/common-session",
        "/etc/pam.d/common-session-noninteractive",
        ".cshrc",
        ".kshrc",
        ".bashrc",
        ".login",
        ".profile"
    ]
    
    path = "/home/" + getpass.getuser() + "/"

    for filename in file_list:
        # 사용자 홈 디렉토리의 파일 경로 설정
        if not filename.startswith("/etc/"):
            filename = os.path.join(path, filename)

        if os.path.isfile(filename):
            with open(filename, mode="r", encoding="utf-8") as handle:
                for line in handle:
                    # 주석이 아닌 줄에서 UMASK 설정 찾기
                    if line[0] != "#":
                        line = line.upper()
                        if "UMASK" in line:
                            line = line.replace(" ", "").replace("\t", "").strip()
                            line = line.split("=")[-1].split(":")[-1]  # UMASK 값 추출

                            if line.isdecimal() and int(line) < 22:
                                report_data["결과"] = "취약"
                                flag = True

    if not flag:
        report_data["결과"] = "양호"

    return report_data
                           
# U-58: 홈 디렉터리 권한 검사
def U58():
    report_data = {
        "항목코드": "U-58",
        "중요도": "중",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False
    path = "/etc/passwd"

    if os.path.isfile(path):
        with open(path, mode="r", encoding="utf-8") as handle:
            for line in handle:
                if line.count(":") == 6 and line[0] != "#":
                    user_info = line.split(":")
                    home_dir = user_info[5]
                    if os.path.isdir(home_dir):
                        permissions = subprocess.getoutput(f"ls -ldL {home_dir}").split()
                        if permissions[0][8] == "w":
                            flag = True
                        if permissions[2] != "root" and permissions[2] != user_info[0] and permissions[3] != user_info[0]:
                            flag = True

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data


# U-59: 홈 디렉터리 상태 검사
def U59():
    report_data = {
        "항목코드": "U-59",
        "중요도": "하",
        "결과": "",
        "분류": "파일및디렉터리관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False
    path = "/etc/passwd"

    if os.path.isfile(path):
        with open(path, mode="r", encoding="utf-8") as handle:
            for line in handle:
                line = line.replace(" ", "").replace("\t", "").replace("\n", "")
                if line.count(":") == 6 and line[0] != "#":
                    user_data = line.split(":")
                    if user_data[5] == "":
                        flag = True
                    if user_data[5] == "/":
                        flag = True

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data


# U-19: finger 서비스 설치 여부 검사
def U19():
    report_data = {
        "항목코드": "U-19",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False

    # Debian 계열에서 finger 설치 여부 확인
    output = subprocess.getoutput("dpkg --get-selections | grep finger")
    output = output.split()
    if output == ['finger', 'install']:
        flag = True

    # Redhat 계열에서 finger 설치 여부 확인
    else:
        output = subprocess.getoutput("finger")
        output = output.split()
        if output and output[0] == "Login" and output[1] == "Name" and output[2] == "Tty":
            flag = True

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

                    
# U-20: Anonymous FTP 계정 비활성화 검사
def U20():
    report_data = {
        "항목코드": "U-20",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False
    f_output = "[U-20] Anonmous FTP 계정 비활성화 검사\n"

    # FTP User Check
    with open("/etc/passwd", mode='r', encoding='utf-8') as handle:
        for line in handle:
            temp = line.upper().replace(" ", "")  # Upper Change and Space Del
            if temp[0] != "#" and "FTP" in temp:  # FTP user check
                f_output += "\t[알림] FTP 계정이 존재합니다.\n"
                f_output += "\t\t따라서 FTP 계정에 대한 확인이 필요합니다.\n"
                flag = True
                break

    if not flag:
        f_output += "\t[알림] FTP 계정이 존재하지 않습니다.\n"

    # FTP Setting File Check
    ftp_configs = ["vsftpd", "vsftpd/vsftpd", "proftpd/proftpd"]
    for config in ftp_configs:
        config_path = f"/etc/{config}.conf"
        if os.path.isfile(config_path):  # if setting file exist
            f_output += f"\t[알림] {config.split('/')[0]} FTP 프로그램 설정 파일이 존재합니다.\n"
            with open(config_path, mode='r', encoding='utf-8') as handle:
                for line in handle:
                    temp = line.upper().replace(" ", "")  # Upper Change and Space Del
                    if temp[0] != "#":  # Remark Del
                        if "VSFTPD" in config:  # /etc/vsftpd.conf Check
                            if "ANONYMOUS_ENABLE=YES" in temp:
                                flag = True
                        else:  # /etc/proftpd.conf Check
                            if "<ANONYMOUS~FTP>" in temp:
                                flag = True

            if flag:  # Result Print
                f_output += "\t[경고] /etc/" + config + ".conf : anonymous 계정 접속이 활성화되어 있습니다.\n"
                f_output += "\t[검사 결과] 보안 조치가 필요합니다.\n"
                flag = False
            else:
                f_output += "\t[검사 결과] 안전합니다.\n"

    # if (FTP user found) && (setting file not found) -> report
    if "[검사 결과]" not in f_output:
        f_output += "\t[알림] FTP 프로그램 설정 파일이 존재하지 않습니다.\n"
        if "FTP 계정이 존재합니다." in f_output:
            f_output += "\t[검사 결과] 보안 조치가 필요합니다.\n"
        elif "FTP 계정이 존재하지 않습니다." in f_output:
            f_output += "\t[검사 결과] 안전합니다.\n"

    # U-20 Report
    if "[검사 결과]" in f_output and "보안 조치가 필요합니다." in f_output:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-21: r 계열 서비스 비활성화 검사
def U21():
    report_data = {
        "항목코드": "U-21",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    f_output = "[U-21] r 계열 서비스 비활성화 검사\n"
    flag = False
    services = ["rlogin", "rsh", "rexec"]

    for service in services:
        path = f"/etc/xinetd.d/{service}"

        if os.path.isfile(path):
            with open(path, mode='r', encoding='utf-8') as handle:
                temp = handle.read()

            temp = temp.replace(" ", "").upper()
            if "DISABLE=YES" not in temp:
                f_output += f"\t[경고] {path} : r계열 서비스가 비활성화 되어 있지 않습니다.\n"
                flag = True

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-22: Cron 관련 설정 파일 점검
def U22():
    report_data = {
        "항목코드": "U-22",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
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
                flag = True

            if owner != "root":
                f_output += f"\t[경고] {file} : 파일의 소유자가 root 계정이 아닙니다.\n"
                flag = True

    # /etc/cron.allow 파일이 없고 /etc/cron.deny 파일만 있는 경우
    if os.path.isfile(files[1]) and not os.path.isfile(files[0]):
        f_output += f"\t[경고] /etc/cron.deny : 해당 파일만 존재하면 취약합니다.\n"
        flag = True

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-23: DoS 공격에 취약한 서비스 비활성화 검사
def U23():
    report_data = {
        "항목코드": "U-23",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
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
                            f_output += f"{C_YELLOW}\t[경고] {inetd_path} : 해당 파일에 DoS 공격에 취약한 서비스({service})가 활성화 되어 있습니다.{C_END}\n"
                            flag = True

    # /etc/xinetd.d/ Scan
    xinetd_path = "/etc/xinetd.d/"
    for service in vulnerable_services:
        service_path = os.path.join(xinetd_path, service)
        if os.path.isfile(service_path):
            with open(service_path, mode="r", encoding="utf-8") as handle:
                data = handle.read().replace(" ", "").replace("\t", "").upper()
                if data.count("{") != data.count("DISABLE=YES"):
                    f_output += f"{C_YELLOW}\t[경고] {service_path} : 해당 파일에 DoS 공격에 취약한 서비스가 활성화 되어 있습니다.{C_END}\n"
                    flag = True

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-24: NFS 서비스 비활성화 검사
def U24():
    report_data = {
        "항목코드": "U-24",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    f_output = "[U-24] NFS 서비스 비활성화 검사\n"
    flag = False

    # NFS 서비스 체크
    temp = subprocess.getoutput("ps -ef | egrep 'nfsd|statd|lockd'")
    if "[nfsd]" in temp or "[statd]" in temp or "[lockd]" in temp:
        flag = True

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-25: NFS 서비스 접근 통제 검사
def U25():
    report_data = {
        "항목코드": "U-25",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False
    path = "/etc/exports"

    if os.path.isfile(path):
        # 파일 권한 및 소유자 체크
        temp = subprocess.getoutput("ls -al " + path).split()
        
        # 파일이 다른 사용자에게 수정 가능 여부 확인
        if temp[0][8] != "-":
            flag = True

        # 소유자 확인
        if temp[2] != "root":
            flag = True

        # 설정 파일 내용 체크
        with open(path, mode="r", encoding="utf-8") as handle:
            data = ""
            for line in handle:
                cleaned_line = line.replace(" ", "").replace("\t", "").replace("\n", "").upper()
                if cleaned_line and cleaned_line[0] != "#":
                    data += cleaned_line

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data
        
# U-26: automountd 설치 검사
def U26():
    report_data = {
        "항목코드": "U-26",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False

    temp = subprocess.getoutput("ps -ef | grep autofs")

    if "autofs.pid" in temp:
        flag = True

    if flag:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-27: 불필요한 RPC 서비스 검사
def U27():
    report_data = {
        "항목코드": "U-27",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False
    rpc_services = "rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd"
    rpc_services = rpc_services.split()

    # /etc/inetd.conf 파일 검사
    path = "/etc/inetd.conf"
    if os.path.isfile(path):
        with open(path, mode="r", encoding="utf-8") as handle:
            data = ""
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    data += line.upper() + "\n"

            for service in rpc_services:
                if service.upper() in data:
                    report_data["결과"] = "취약"
                    flag = True

    # /etc/xinetd.d/ 디렉터리 검사
    xinetd_path = "/etc/xinetd.d/"
    for service in rpc_services:
        if os.path.isfile(os.path.join(xinetd_path, service)):
            with open(os.path.join(xinetd_path, service), mode="r", encoding="utf-8") as handle:
                data = ""
                for line in handle:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        data += line.upper() + "\n"

                if "DISABLE=YES" not in data:
                    report_data["결과"] = "취약"
                    flag = True

    # 결과가 없으면 양호로 설정
    if not flag:
        report_data["결과"] = "양호"

    return report_data

# U-28: NIS, NIS+ 서비스 검사
def U28():
    report_data = {
        "항목코드": "U-28",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False

    # NIS, NIS+ 서비스 검사 명령 실행
    temp = subprocess.getoutput("ps -ef | egrep \"ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated\" | grep -v grep")

    if len(temp) != 0:
        flag = True
        report_data["결과"] = "취약"

    # 결과가 없으면 양호로 설정
    if not flag:
        report_data["결과"] = "양호"

    return report_data

# U-29: tftp, talk 서비스 검사
def U29():
    report_data = {
        "항목코드": "U-29",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    flag = False
    services_list = ["tftp", "talk", "ntalk"]

    # /etc/inetd.conf 파일 검사
    inetd_path = "/etc/inetd.conf"
    if os.path.isfile(inetd_path):
        with open(inetd_path, mode="r", encoding="utf-8") as handle:
            data = handle.read().replace(" ", "").replace("\t", "").replace("\n", "").upper()
            for service in services_list:
                if service.upper() in data:
                    report_data["결과"] = "취약"
                    flag = True

    # /etc/xinetd.d 디렉토리 검사
    xinetd_path = "/etc/xinetd.d/"
    for service in services_list:
        service_file = os.path.join(xinetd_path, service)
        if os.path.isfile(service_file):
            with open(service_file, mode="r", encoding="utf-8") as handle:
                data = handle.read().replace(" ", "").replace("\t", "").replace("\n", "").upper()
                if "DISABLE=YES" not in data:
                    report_data["결과"] = "취약"
                    flag = True

    # 모든 검사가 양호한 경우
    if not flag:
        report_data["결과"] = "양호"

    return report_data

# U-30: Sendmail 서비스 검사
def U30():
    report_data = {
        "항목코드": "U-30",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    isSendmailRunning = False
    temp = subprocess.getoutput("ps -ef | grep sendmail")

    # Sendmail 서비스 실행 여부 확인
    if len(temp) != 0:
        temp = temp.split("\n")
        for i in temp:
            if "grep" not in i:
                isSendmailRunning = True
                report_data["결과"] = "취약"
                break

    # Sendmail 서비스가 실행 중인 경우 조치 방법 안내
    if isSendmailRunning:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-31: 스팸 메일 릴레이 제한 검사
def U31():
    report_data = {
        "항목코드": "U-31",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    isSpamRelayRestricted = True

    # /etc/mail/sendmail.cf 파일 검사
    if os.path.isfile("/etc/mail/sendmail.cf"):
        temp = subprocess.getoutput("cat /etc/mail/sendmail.cf | grep 'R$*' | grep 'Relaying denied'")
        if len(temp) == 0 or temp[0] == "#":
            isSpamRelayRestricted = False
            report_data["결과"] = "취약"
        
        # /etc/mail/access 파일 유무 확인
        if not os.path.isfile("/etc/mail/access"):
            isSpamRelayRestricted = False
            report_data["결과"] = "취약"

    if isSpamRelayRestricted:
        report_data["결과"] = "양호"

    return report_data

# U-32: 일반 사용자의 Sendmail 실행 방지
def U32():
    report_data = {
        "항목코드": "U-32",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    is_safe = True

    # Sendmail 프로세스가 실행 중인지 확인
    sendmail_process = subprocess.getoutput('ps -ef | grep sendmail | grep -v "grep"')

    if 'sendmail' in sendmail_process:
        # sendmail.cf에서 PrivacyOptions 옵션 확인
        privacy_options = subprocess.getoutput('grep -v "^ *#" /etc/mail/sendmail.cf | grep PrivacyOptions')

        if 'restrictqrun' not in privacy_options:
            report_data["결과"] = "취약"
            is_safe = False
    else:
        report_data["결과"] = "양호"

    if is_safe:
        report_data["결과"] = "양호"

    return report_data

# U-33: DNS 보안 버전 패치
def U33():
    report_data = {
        "항목코드": "U-33",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # 'named' 프로세스가 실행 중인지 확인
    out = subprocess.getoutput('ps -ef | grep named 2>/dev/null')

    if 'named' in out and 'grep' not in out:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# DNS Zone Transfer 설정
def U34():
    report_data = {
        "항목코드": "U-34",
        "중요도": "상",  
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }
    
    out = subprocess.getoutput('ps -ef | grep named | grep -v "grep"')

    if 'named' in out:
        out = subprocess.getoutput('cat /etc/bind/named.conf')
        if 'allow-transfer' not in out or 'xfrnets' not in out:
            report_data["결과"] = "취약"
        else:
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "양호"
    
    return report_data

def U35():
    report_data = {
        "항목코드": "U-35",
        "중요도": "상",  
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # Apache의 홈 디렉토리를 확인
    out = subprocess.getoutput('apache2 -V | egrep "(HTTPD_ROOT|SERVER_CONFIG_FILE)"')

    if 'HTTPD_ROOT=' in out:
        # 사용자의 Apache 홈 디렉토리를 추출
        index1 = out.find('HTTPD_ROOT="')
        index2 = out.find('"', index1 + 13)
        apacheHome = out[index1 + 12:index2]

        index1 = out.find('SERVER_CONFIG_FILE="')
        index2 = out.find('"', index1 + 21)
        apacheConf = apacheHome + "/" + out[index1 + 20:index2]

        # Apache 설정 파일 존재 여부 확인
        if os.path.exists(apacheConf):
            with open(apacheConf, 'r') as f:
                content = f.read()
            # Directory 설정 개수 검색
            count = content.count('<Directory')
            index = 0
            for _ in range(count):
                # <Directory> 블록 찾기
                index1 = content.find('<Directory', index)
                # 주석 처리 확인
                if re.search(r'#\s*<Directory', content[index:index1 + 10]):
                    index = content.find('</Directory>', index1) + 12
                    continue
                index2 = content.find('</Directory>', index1)
                directory_block = content[index1:index2]
                index = index2 + 12
                # Indexes 옵션 확인
                if 'Indexes' in directory_block:
                    report_data["결과"] = "취약"
                    break
            else:
                report_data["결과"] = "양호"
        else:
            # Apache 설정 파일이 존재하지 않을 경우
            report_data["결과"] = "취약"
    else:
        # Apache 서비스를 사용하지 않을 경우
        report_data["결과"] = "양호"

    return report_data

# U-36: Apache 웹 프로세스 권한 제한
def U36():
    report_data = {
        "항목코드": "U-36",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    out = subprocess.getoutput('apache2 -V | egrep "(HTTPD_ROOT|SERVER_CONFIG_FILE)"')

    if 'HTTPD_ROOT=' in out:
        # Extract Apache home directory
        index1 = out.find('HTTPD_ROOT="')
        index2 = out.find('"', index1 + 13)
        apacheHome = out[index1 + 12:index2]

        index1 = out.find('SERVER_CONFIG_FILE="')
        index2 = out.find('"', index1 + 21)
        apacheConf = apacheHome + "/" + out[index1 + 20:index2]

        out = subprocess.getoutput('cat ' + apacheConf)

        if 'User root' in out or 'Group root' in out:
            report_data["결과"] = "취약"
        else:
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-37: Apache 상위 디렉토리 접근 금지
def U37():
    report_data = {
        "항목코드": "U-37",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    out = subprocess.getoutput('apache2 -V | egrep "(HTTPD_ROOT|SERVER_CONFIG_FILE)"')

    if 'HTTPD_ROOT=' in out:
        # Extract Apache home directory
        index1 = out.find('HTTPD_ROOT="')
        index2 = out.find('"', index1 + 13)
        apacheHome = out[index1 + 12:index2]

        index1 = out.find('SERVER_CONFIG_FILE="')
        index2 = out.find('"', index1 + 21)
        apacheConf = apacheHome + "/" + out[index1 + 20:index2]

        out = subprocess.getoutput('cat ' + apacheConf)

        if 'AllowOverride None' in out:
            report_data["결과"] = "취약"
        else:
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-38: Apache 불필요한 파일 제거
def U38():
    report_data = {
        "항목코드": "U-38",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    out = subprocess.getoutput('apache2 -V | egrep "(HTTPD_ROOT|SERVER_CONFIG_FILE)"')

    if 'HTTPD_ROOT=' in out:
        # Extract Apache home directory
        index1 = out.find('HTTPD_ROOT="')
        index2 = out.find('"', index1 + 13)
        apacheHome = out[index1 + 12:index2] + "/"

        # Check for the presence of unnecessary files or directories (e.g., 'manual')
        out = subprocess.getoutput(f'find {apacheHome}htdocs/ -name manual 2> /dev/null')

        if 'manual' in out:
            report_data["결과"] = "취약"
        else:
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-39: Apache 링크 사용 금지
def U39():
    report_data = {
        "항목코드": "U-39",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    report = False
    out = subprocess.getoutput('apache2 -V | egrep "(HTTPD_ROOT|SERVER_CONFIG_FILE)"')

    if 'HTTPD_ROOT=' in out:
        # Extract Apache home directory
        index1 = out.find('HTTPD_ROOT="')
        index2 = out.find('"', index1 + 13)
        apacheHome = out[index1 + 12:index2]

        index1 = out.find('SERVER_CONFIG_FILE="')
        index2 = out.find('"', index1 + 21)
        apacheHome = apacheHome + "/" + out[index1 + 20:index2]

        out = subprocess.getoutput('cat ' + apacheHome)

        # Count number of <Directory> settings
        count = out.count('<Directory')
        index = 0

        for i in range(count):
            index1 = out.find('<Directory', index)

            # Skip if it's a comment
            if re.search('#<Directory', out[index:index1 + 10]) or re.search('#\s+<Directory', out[index:index1 + 10]):
                index = out.find('</Directory>', index1 + 13)
                continue

            index2 = out.find('</Directory>', index1 + 13)
            out1 = out[index1 + 10:index2]
            index = index1 + 10

            if 'FollowSymLinks' in out1:
                report = True
                report_data["결과"] = "취약"
                break

        if not report:
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-40: Apache 파일 업로드 및 다운로드 제한
def U40():
    report_data = {
        "항목코드": "U-40",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    report = False
    # Check Apache home directory
    out = subprocess.getoutput('apache2 -V | egrep "(HTTPD_ROOT|SERVER_CONFIG_FILE)"')

    if 'HTTPD_ROOT=' in out:
        # Extract user's Apache home directory
        index1 = out.find('HTTPD_ROOT="') 
        index2 = out.find('"', index1 + 13)
        apacheHome = out[index1 + 12:index2]

        index1 = out.find('SERVER_CONFIG_FILE="')
        index2 = out.find('"', index1 + 21)
        apacheHome = apacheHome + "/" + out[index1 + 20:index2]

        out = subprocess.getoutput('cat ' + apacheHome)

        # Count number of <Directory> settings
        count = out.count('<Directory')

        index = 0
        for i in range(count):
            index1 = out.find('<Directory', index)

            # Skip if it's a comment
            if re.search('#<Directory', out[index:index1 + 10]) or re.search('#\s+<Directory', out[index:index1 + 10]):
                index = out.find('</Directory>', index1 + 13)
                continue

            index2 = out.find('</Directory>', index1 + 13)
            out1 = out[index1 + 10:index2]
            index = index1 + 10

            if 'LimitRequestBody' in out1:
                # Extract the number
                num = re.findall("LimitRequestBody\s+\d+", out1)
                num[0] = re.findall("\d+", num[0])
                num = list(map(int, num[0]))

                # If it's greater than 5M, report as vulnerable
                if num[0] > 5000000:
                    report = True
                    report_data["결과"] = "취약"
                    break
                else:
                    continue

        if not report:
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-41: Apache 웹 서비스 영역의 분리
def U41():
    report_data = {
        "항목코드": "U-41",
        "중요도": "상",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    report = False
    # Check DocumentRoot in configuration files
    out = subprocess.getoutput('grep -i "DocumentRoot" /etc/apache2/sites-available/000-default.conf ; grep -i "DocumentRoot" /etc/apache2/sites-available/default-ssl.conf')

    if 'DocumentRoot' in out:
        if ('/usr/local/apache/htdocs' in out) or ('/usr/local/apache2/htdocs' in out) or ('/var/www/html' in out):
            report = True
            report_data["결과"] = "취약"
        else:
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-60: SSH 원격접속 허용
def U60():
    report_data = {
        "항목코드": "U-60",
        "중요도": "중",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    report = False
    # Check the status of SSH service
    out = subprocess.getoutput('service ssh status')
    
    if ('not be found' in out) or ('not found' in out) or ('unrecognized' in out):
        report = True
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-61: FTP 서비스 확인
def U61():
    report_data = {
        "항목코드": "U-61",
        "중요도": "하",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # Check for FTP service
    out = subprocess.getoutput('ps -ef | grep ftp & ps -ef | egrep "vsftpd|proftp"')
    
    if ('ftp' in out) or ('vsftpd' in out) or ('proftp' in out):
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data


# U-62: FTP 계정 shell 제한
def U62():
    report_data = {
        "항목코드": "U-62",
        "중요도": "중",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # Check for FTP account shell
    out = subprocess.getoutput('cat /etc/passwd | grep "ftp"')

    if 'ftp:/bin/false' in out:
        report_data["결과"] = "양호"
    else:
        report_data["결과"] = "취약"

    return report_data


# U-63: ftpusers 파일 소유자 및 권한 설정
def U63():
    report_data = {
        "항목코드": "U-63",
        "중요도": "하",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    def check_mod(out):
        st = os.stat(out)
        perm = oct(st.st_mode)

        # Check permissions
        perm = int(perm[5:8])
        re1 = perm > 640

        # Check owner
        owner = getpwuid(st.st_uid).pw_name
        re2 = owner != "root"

        # Vulnerable if either condition is met
        return re1 or re2

    # Check /etc/ftpusers
    report = False
    if os.path.exists('/etc/ftpusers'):
        report = check_mod('/etc/ftpusers')

    # Check /etc/ftpd/ftpusers
    if os.path.exists('/etc/ftpd/ftpusers'):
        report = report or check_mod('/etc/ftpd/ftpusers')

    if report:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data


# U-64: ftpusers 파일 설정
def U64():
    report_data = {
        "항목코드": "U-64",
        "중요도": "중",  
        "결과": "", 
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    out = subprocess.getoutput('cat /etc/ftpusers 2>/dev/null') + subprocess.getoutput('cat /etc/ftpd/ftpusers 2>/dev/null')

    # root 항목 검사
    if 'root' in out:
        if ('#root' in out) or re.search('#\s+root', out):
            report_data["결과"] = "양호"  # 주석 처리된 경우
        else:
            report_data["결과"] = "취약"

    # 모든 검사가 양호할 경우 진단결과 수정
    if report_data["결과"] == "":
        report_data["결과"] = "양호"

    return report_data


# U-65: at 파일 소유자 및 권한 설정
def U65():
    report_data = {
        "항목코드": "U-65",
        "중요도": "중",  
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    report1 = False
    report2 = False

    # /etc/at.allow 파일 검사
    at_allow_path = '/etc/at.allow'
    if os.path.exists(at_allow_path):
        report1 = not check_mod(at_allow_path)

    # /etc/at.deny 파일 검사
    at_deny_path = '/etc/at.deny'
    if os.path.exists(at_deny_path):
        report2 = not check_mod(at_deny_path)

    report = report1 or report2

    if report:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"  # 모든 검사가 양호할 경우

    return report_data

# U-66: SNMP 서비스 구동 점검
def U66():
    report_data = {
        "항목코드": "U-66",
        "중요도": "중",  # 중요도는 비워둡니다
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    out = subprocess.getoutput('ps -ef | grep snmp')

    if 'snmp' in out:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"  # SNMP 서비스가 실행 중이지 않을 경우

    return report_data

# U-67: SNMP 서비스 Community String의 복잡성 설정
def U67():
    report_data = {
        "항목코드": "U-67",
        "중요도": "중",  # 중요도는 비워둡니다
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    report = False

    # SNMP 설정 파일 조회
    out = subprocess.getoutput('sudo cat /etc/snmp/snmpd.conf')

    index = -1
    newindex = 0
    while True:
        index = out.find("rocommunity", index + 1)
        if index == -1:
            break

        out2 = out[newindex:index + 20]
        newindex = index

        if re.search('#rocommunity', out2) or re.search('#\s+rocommunity', out2):
            index = out.find("rocommunity", index + 1)
            if index == -1:
                break
            out2 = out[newindex:index + 20]
            newindex = index
            continue

        if re.search('rocommunity\s+public', out2) or re.search('rocommunity6\s+public', out2):
            report = True
            break

    if report:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"  # Community String이 안전하게 설정되어 있을 경우

    return report_data

# U-68: 로그온 시 경고 메시지 제공
def U68():
    report_data = {
        "항목코드": "U-68",
        "중요도": "하",  
        "결과": "", 
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }
    
    # 경고 메시지가 설정되지 않은 경우 취약점으로 간주
    report_data["결과"] = "취약"

    return report_data

# U-69: NFS 설정파일 접근권한
def U69():
    report_data = {
        "항목코드": "U-69",
        "중요도": "중",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    def check_mod(out):
        st = os.stat(out)
        perm = oct(st.st_mode)

        perm = int(perm[5:8])
        if perm > 644:
            re1 = True
        else:
            re1 = False

        owner = getpwuid(stat(out).st_uid).pw_name
        if owner == "root":
            re2 = True
        else:
            re2 = False

        return re1 or re2

    out = '/etc/exports'
    if os.path.exists(out):
        report = check_mod(out)
        
        if report:
            report_data["결과"] = "취약"
        else:
            report_data["결과"] = "양호"
    else:
        report_data["결과"] = "취약"

    return report_data

# U-70: expn, vrfy 명령어 제한
def U70():
    report_data = {
        "항목코드": "U-70",
        "중요도": "중",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    out = subprocess.getoutput('cat /etc/mail/sendmail.cf')

    # PrivacyOptions 부터 # 까지
    index = out.find("PrivacyOptions")
    index2 = out.find("#", index + 1)

    # noexpn과 novrfy 옵션 검사
    noexpn = 'noexpn' in out[index:index2]
    novrfy = 'novrfy' in out[index:index2]

    if not noexpn or not novrfy:
        report_data["결과"] = "취약"
    else:
        report_data["결과"] = "양호"

    return report_data

# U-71: Apache 웹 서비스 정보 숨김
def U71():
    report_data = {
        "항목코드": "U-71",
        "중요도": "중",
        "결과": "",
        "분류": "서비스관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # Apache의 홈 디렉토리를 확인
    out = subprocess.getoutput('apache2 -V | egrep "(HTTPD_ROOT|SERVER_CONFIG_FILE)"')

    if 'HTTPD_ROOT=' in out:
        # 사용자의 Apache 홈 디렉토리를 추출
        index1 = out.find('HTTPD_ROOT="') 
        index2 = out.find('"', index1 + 13)
        apacheHome = out[index1 + 12:index2]

        index1 = out.find('SERVER_CONFIG_FILE="')
        index2 = out.find('"', index1 + 21)
        apacheHome = apacheHome + "/" + out[index1 + 20:index2]

        out = subprocess.getoutput('cat ' + apacheHome)

        # Directory 설정 개수 검색
        count = out.count('<Directory')
        report = False

        for i in range(count):
            # <Directory /> </Directory> 사이에 포함된 옵션
            index1 = out.find('<Directory', index1 if i == 0 else index + 1)

            # 주석 처리가 되어있다면 건너뜀
            if re.search(r'#<Directory', out[index1:index1 + 10]) or re.search(r'#\s+<Directory', out[index1:index1 + 10]):
                index = out.find('</Directory>', index1 + 13)
                continue

            index2 = out.find('</Directory>', index1 + 13)
            out1 = out[index1 + 10:index2]
            index = index2

            # ServerTokens 및 ServerSignature 검사
            if not re.search(r'ServerTokens\s+Prod', out1):
                report_data["결과"] = "취약"
                return report_data
            
            if not re.search(r'ServerSignature\s+Off', out1):
                report_data["결과"] = "취약"
                return report_data

        report_data["결과"] = "양호"  # 모든 점검이 통과하면 '양호'

    # Apache가 없음
    else:
        report_data["결과"] = "취약"

    return report_data

# U-42: 최신 보안패치 및 벤더 권고사항 적용
def U42():
    report_data = {
        "항목코드": "U-42",
        "중요도": "상",
        "결과": "",
        "분류": "패치관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    try:
        # 보안 업데이트 확인 명령 실행 (dry-run 모드로 패키지 업그레이드를 시뮬레이션)
        update_check = subprocess.getoutput('sudo apt-get -s dist-upgrade')

        # 보안 패치 적용 여부 판정
        if "0 upgraded" in update_check:
            # 양호: 적용할 업데이트가 없는 경우
            report_data["결과"] = "양호"
        else:
            # 취약: 업데이트가 필요한 경우
            report_data["결과"] = "취약"
    
    except Exception as e:
        # 오류 발생 시 취약으로 처리
        report_data["결과"] = "취약"

    return report_data

# U-43: 로그의 정기적 검토 및 보고
def U43(): 
    report_data = {
        "항목코드": "U-43",
        "중요도": "상",
        "결과": "수동 점검",
        "분류": "패치관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }
    user = getpass.getuser()
    cpath = f"/home/{user}/LOG"
    if not os.path.exists(cpath):
        os.makedirs(cpath)

    subprocess.call('last > ~/LOG/wtmp_log.txt', shell=True)
    subprocess.call('sudo lastb > ~/LOG/btmp_log.txt', shell=True)
    subprocess.call('w > ~/LOG/utmp_log.txt', shell=True)

    if os.path.exists('/var/log/sulog'):
        subprocess.call('cat /var/log/sulog > ~/LOG/sulog.txt', shell=True)

    if os.path.exists('/var/log/xferlog'):
        subprocess.call('cat /var/log/xferlog > ~/LOG/xferlog.txt', shell=True)

    report_data["결과"] = "수동 점검 필요"

    return report_data

# U-72: 정책에 따른 시스템 로깅 설정
def U72():
    report_data = {
        "항목코드": "U-72",
        "중요도": "하",
        "결과": "",
        "분류" : "로그관리",
        "hwid": "58814d56-48b0-5981-048e-04f9f5a1a8a4",
        "점검대상": "Ubuntu 22.04_2",
        "점검자": "김가현"
    }

    # rsyslog.conf 파일 검사
    try:
        with open('/etc/rsyslog.conf', 'r') as file:
            config = file.read()

        # 로그 정책을 위한 설정을 검사합니다.
        if not all(option in config for option in ['*.info;mail.none;;authpriv.none;cron.none', 
                                                     'authpriv.*', 
                                                     'mail.*', 
                                                     'cron.*']):
            report_data["결과"] = "취약"

    except FileNotFoundError:
        report_data["결과"] = "취약"

    return report_data

# 메인 함수
def main():
    
    final_report = []

    final_report.append(U01()) 
    final_report.append(U02())
    final_report.append(U03())
    final_report.append(U04())
    final_report.append(U44())
    final_report.append(U45())
    final_report.append(U46())
    final_report.append(U47())
    final_report.append(U48())
    final_report.append(U49())
    final_report.append(U50())
    final_report.append(U51())
    final_report.append(U52())
    final_report.append(U53())
    final_report.append(U54())
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
    final_report.append(U55())
    final_report.append(U56())
    final_report.append(U57())
    final_report.append(U58())
    final_report.append(U59())
    final_report.append(U19())
    final_report.append(U20())
    final_report.append(U21())
    final_report.append(U22())
    final_report.append(U23())
    final_report.append(U24())
    final_report.append(U25())
    final_report.append(U26())
    final_report.append(U27())
    final_report.append(U28())
    final_report.append(U29())
    final_report.append(U30())
    final_report.append(U31())
    final_report.append(U32())
    final_report.append(U33())
    final_report.append(U34())
    final_report.append(U35())
    final_report.append(U36())
    final_report.append(U37())
    final_report.append(U38())
    final_report.append(U39())
    final_report.append(U40())
    final_report.append(U41())
    final_report.append(U60())
    final_report.append(U61())
    final_report.append(U62())
    final_report.append(U63())
    final_report.append(U64())
    final_report.append(U65())
    final_report.append(U66())
    final_report.append(U67())
    final_report.append(U68())
    final_report.append(U69())
    final_report.append(U70())
    final_report.append(U71())
    final_report.append(U42())
    final_report.append(U43())
    final_report.append(U72())

    
    # 항목 개수, 취약 개수, 양호 개수 카운트 (결과가 있는 항목만 대상)
    total_items = len([item for item in final_report if "결과" in item])
    good_items = sum(1 for item in final_report if item.get("결과") == "양호")
    vulnerable_items = sum(1 for item in final_report if item.get("결과") == "취약")
    manual_check_items = sum(1 for item in final_report if item.get("결과") == "수동 점검 필요")

    # 결과 요약 추가
    summary = {
        "항목 개수": total_items,
        "양호 개수": good_items,
        "취약 개수": vulnerable_items,
        "수동 점검": manual_check_items
    }

# 결과 요약을 final_report에 추가
    final_report.append(summary)


    # # 리스트만 저장 (진단 항목 리스트만 포함)
    # json_file_path = './logs/check.json'
    

    # # with 블록 내의 코드가 들여쓰기 되어야 합니다.
    # with open(json_file_path, 'w', encoding='utf-8') as json_file:
    #     json.dump(final_report, json_file, ensure_ascii=False, indent=4)



    json_file_path = './logs/check.json'
    with open(json_file_path, 'w', encoding='utf-8') as json_file:
        json.dump(final_report, json_file, ensure_ascii=False, indent=4)

    logstash_loader.run_loader()
    # # 콘솔에 결과 출력 (리스트만 출력)
    # print(json.dumps(final_report, ensure_ascii=False, indent=4))


# 스크립트를 실행할 때 main() 함수를 호출합니다.
if __name__ == "__main__":
    main()

      


