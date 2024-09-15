# import frida
#
#
#
# # session = frida.attach("PizzaBusiness.exe")
# # session = frida.attach(14656)
#
#
# game_pid = frida.spawn("D:\\GRY\\Good Pizza, Great Pizza\\PizzaBusiness.exe", ["-l", "-pause"])
# session = frida.attach(game_pid)
#
# script_file = open("frida_hook.js", "rt")
# script_file_content: str = script_file.read()
# script_file.close()
# script = session.create_script(script_file_content)
# script.load()
