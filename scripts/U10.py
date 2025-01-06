from os import path, stat
import printModule as pm

def U10():
    report = pm.openReport('U-10.txt')
    pm.printTitle(report, '[U-10] /etc/(x)inetd.conf 파일 소유자 및 권한 설정')

    # 확인할 파일 경로 변수
    filename = None

    # /etc/inetd.conf 파일 존재 여부 확인
    isInetd = path.isfile('/etc/inetd.conf')
    if isInetd:
        filename = '/etc/inetd.conf'
        pm.printNotice(report, '/etc/inetd.conf 파일이 존재합니다.')
    
    # /etc/xinetd.conf 파일 존재 여부 확인
    isXinetd = path.isfile('/etc/xinetd.conf')
    if isXinetd:
        filename = '/etc/xinetd.conf'
        pm.printNotice(report, '/etc/xinetd.conf 파일이 존재합니다.')

    # 둘 다 없는 경우 처리
    if not isInetd and not isXinetd:
        pm.printNotice(report, '/etc/inetd.conf 파일도, /etc/xinetd.conf 파일도 존재하지 않습니다.')
        report.close()
        return

    # 파일 상태 확인
    status = stat(filename)

    # 소유자 확인
    isRightOwner = False
    owner = status.st_uid
    if owner == 0:
        isRightOwner = True
        pm.printNotice(report, filename + ' 파일의 소유자가 root 입니다.')
    else:
        pm.printWarning(report, filename + ' 파일의 소유자가 root가 아닙니다.')

    # 권한 확인
    isRightPerm = False
    perm = int(oct(status.st_mode)[-3:])
    if perm == 600:
        isRightPerm = True
        pm.printNotice(report, filename + ' 파일의 권한이 600 입니다.')
    else:
        pm.printWarning(report, filename + ' 파일의 권한이 600이 아닙니다.')

    # 최종 상태 확인
    if isRightOwner and isRightPerm:
        pm.printSafe(report)
    else:
        pm.printNotsafe(report)
        pm.printSolution(report, '[U-10] 조치 방법')
        pm.printSolution(report, '\t' + filename + ' 파일의 소유자를 root로 권한을 600으로 변경하세요.')
        pm.printSolution(report, '\t\t#chown root ' + filename)
        pm.printSolution(report, '\t\t#chmod 600 ' + filename)

    # xinetd.d 디렉터리 하위 파일 검사 추가
    if isXinetd:
        pm.printSolution(report, '\t/etc/xinetd.d 디렉터리 하위의 취약한 파일도 동일한 방법으로 조치하세요.')

    report.close()

U10()

