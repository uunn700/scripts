# [U-26] automountd 설치 검사

import subprocess
C_END     = "\033[0m"
C_RED    = "\033[31m"
C_GREEN  = "\033[32m"
C_YELLOW = "\033[33m"
C_NUM = "U-26"

def U26() :
    f_output = ""
    f_output = f_output + "[" + C_NUM + "] automountd 설치 검사" + "\n"
    flag = False

    temp = subprocess.getoutput("ps -ef | grep autofs")

    if (temp.find("autofs.pid") != -1) :
        f_output = f_output + C_YELLOW + "\t[경고] automountd(autofs) 서비스가 활성화 되어 있습니다.\n"
        flag = True

    if (flag) :
        f_output = f_output + C_RED + "\t[검사 결과] 보안 조치가 필요합니다.\n" + C_END  
        f_output = f_output + "\n"
        f_output = f_output + "[" + C_NUM + "] 조치 방법\n"
        f_output = f_output + "\tautomountd(autofs) 관련 패키지를 모두 삭제해주세요.\n"
        f_output = f_output + "\t\t(데비안 계열(우분투 등) : apt remove autofs -y)\n"
        f_output = f_output + "\t\t(레드햇 계열(CentOS 등) : yum install autofs -y)\n" 
    else :
        f_output = f_output + C_GREEN + "\t[검사 결과] 안전합니다.\n" + C_END
        f_output = f_output + "\n"

    print(f_output,end='')
    handle = open("./" + C_NUM + ".txt", mode='w', encoding='utf-8')
    handle.write(f_output)
    handle.close()

U26()
