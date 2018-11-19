import my_debugger
import os

debugger = my_debugger.debugger()

#path = b"C:/WINDOWS/System32/calc.exe"

pid = input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))
debugger.run()
debugger.detach()
