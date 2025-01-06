# [U-58] 홈 디렉터리 소유자 및 권한 설정 점검

import os.path
import subprocess

C_END     = "\033[0m"
C_RED    = "\033[31m"
C_GREEN  = "\033[32m"
C_YELLOW = "\033[33m"
C_NUM = "U-58"

def U58() :
    f_output = ""
    f_output = f_output + "[" + C_NUM + "] 홈 디렉터리 소유자 및 권한 설정 점검\n"
    flag = False
    path = "/etc/passwd"

    if (os.path.isfile(path)) :
        handle = open(path, mode="r", encoding="utf-8")
        temp = handle.readline()

        while temp:
            if (temp.count(":") == 6) and (temp[0] != "#"):
                temp = temp.split(":")
                data = temp[5]
                if (os.path.isdir(temp[5])):
                    data = subprocess.getoutput("ls -ldL " + temp[5])
                    data = data.split()
                    if (data[0][8] == "w"):
                        f_output = f_output + C_YELLOW + "\t[경고] "+ temp[0] + " 계정의 홈 디렉터리에 다른 사용자가 파일을 쓸 수 있습니다.\n" + C_END 
                        f_output = f_output + C_YELLOW + "\t\t(홈 디렉터리 경로 : " + temp[5] + ", 현재 권한 : " + data[0] + ")\n" + C_END 
                        flag = True
                    
                    if (data[2] != "root") and (data[2] != temp[0]) and (data[3] != temp[0]):
                        f_output = f_output + C_YELLOW + "\t[경고] "+ temp[0]+ " 계정의 홈 디렉터리 소유주가 root 또는 해당 계정 사용자가 아닙니다.\n" + C_END 
                        f_output = f_output + C_YELLOW + "\t\t(홈 디렉터리 경로 : " + temp[5] + ")\n" + C_END 
                        f_output = f_output + C_YELLOW + "\t\t(소유주 : " + data[2] + ", 소유 그룹 : "  + data[3] + ")\n" + C_END 
                        flag = True
            temp = handle.readline()
        handle.close()

    if (flag) :
        f_output = f_output + C_RED + "\t[검사 결과] 보안 조치가 필요합니다.\n" + C_END  
        f_output = f_output + "\n"
        f_output = f_output + "[" + C_NUM + "] 조치 방법\n"
        f_output = f_output + "\t1. 해당 계정의 홈 디렉터리 폴더에 다른 사용자가 파일을 쓸 수 없도록 하세요.\n"
        f_output = f_output + "\t\t(ex. chmod 755 [홈 디렉터리 폴더 경로])\n"
        f_output = f_output + "\t2. 해당 계정의 홈 디렉터리 폴더 소유주를 해당 계정으로 설정하세요.\n"
        f_output = f_output + "\t\t(ex. chown [계정명]:[그룹명] [홈 디렉터리 폴더 경로])\n"
    else :
        f_output = f_output + C_GREEN + "\t[검사 결과] 안전합니다.\n" + C_END
        f_output = f_output + "\n"

    print(f_output,end='')
    handle = open("./" + C_NUM + ".txt", mode='w', encoding='utf-8')
    handle.write(f_output)
    handle.close()

U58()
