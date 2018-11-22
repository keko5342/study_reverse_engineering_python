import my_debugger
import os

debugger = my_debugger.debugger()

#path = b"C:/WINDOWS/System32/calc.exe"

pid = input("Enter the PID of the process to attach to: ")

debugger.attach(int(pid))
list = debugger.enumerate_threads()
if list is False:
    print("[*] Faild get list")
#else:
#    print(list)

for thread in list:
    context = debugger.get_thread_context(thread)

    print("[*] Dumping regisers for thread ID: 0x%08x" % thread)
    print("[Rip]0x{:016X}".format(context.Rip))
    print("[Rax]0x{:016X}".format(context.Rax))
    print("[Rcx]0x{:016X}".format(context.Rcx))
    print("[Rdx]0x{:016X}".format(context.Rdx))
    print("[Rbx]0x{:016X}".format(context.Rbx))
    print("[Rsp]0x{:016X}".format(context.Rsp))
    print("[Rbp]0x{:016X}".format(context.Rsp))
    print("[Rsi]0x{:016X}".format(context.Rsi))
    print("[Rdi]0x{:016X}".format(context.Rdi))
    print("[*] END DUMP")

debugger.detach()
