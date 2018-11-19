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
    thread_context = debugger.get_thread_context(thread)

    print("[*] Dumping regisers for thread ID: 0x%08x" % thread)
    print("[**] EIP: 0x%08x" % thread_context.Eip)
    print("[**] ESP: 0x%08x" % thread_context.Esp)
    print("[**] EBP: 0x%08x" % thread_context.Ebp)
    print("[**] EAX: 0x%08x" % thread_context.Eax)
    print("[**] EBX: 0x%08x" % thread_context.Ebx)
    print("[**] ECX: 0x%08x" % thread_context.Ecx)
    print("[**] EDX: 0x%08x" % thread_context.Edx)
    print("[*] END DUMP")

debugger.detach()
