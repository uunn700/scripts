
# printModule.py
def openReport(filename):
    return open(filename, 'w')

def printTitle(report, title):
    report.write(title + '\n')

def printWarning(report, message):
    report.write('WARNING: ' + message + '\n')

def printSafe(report):
    report.write('SYSTEM IS SAFE\n')

def printNotsafe(report):
    report.write('SYSTEM IS NOT SAFE\n')

def printSolution(report, solution):
    report.write('SOLUTION: ' + solution + '\n')

def printNotice(report, message):
    report.write("[알림] " + message + "\n")    
