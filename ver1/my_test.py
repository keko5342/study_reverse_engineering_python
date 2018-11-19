import my_debugger
import os

debugger = my_debugger.debugger()

path = b"C:/WINDOWS/System32/calc.exe"
debugger.load(path)

