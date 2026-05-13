import subprocess
import re
import sys

ANSI_COLOR_GREEN = "\x1b[32m"
ANSI_COLOR_RED = "\x1b[31m"
ANSI_COLOR_RESET = "\x1b[0m"

def run_command(args):
	res = subprocess.run(args, capture_output = True)
	return res.stdout

def run_test(args_nmap, args_ft_nmap, protocol):
	output_ft_nmap = run_command(args_ft_nmap)
	output_nmap = run_command(args_nmap)
	output_ft_nmap_utf = output_ft_nmap.decode('utf-8')
	output_nmap_utf = output_nmap.decode('utf-8')

	# Retrieve the port number and status
	searchObj_my_nmap = re.findall(r"(\d+)/{protocol}.*(closed|open|filtered|unfiltered)", output_ft_nmap_utf)
	searchObj_nmap = re.findall(r"(\d+)/{protocol}.*(closed|open|filtered|unfiltered)", output_nmap_utf)

	try:
		assert searchObj_my_nmap == searchObj_nmap
		print(f"{ANSI_COLOR_GREEN}SUCCESS{ANSI_COLOR_RESET}\n")
		return True
	except AssertionError:
		for obj_my_nmap, obj_nmap in zip(searchObj_nmap, searchObj_my_nmap):
			try:
					assert obj_my_nmap == obj_nmap
			except AssertionError:
					print(f"{ANSI_COLOR_RED}Different status given for port {obj_nmap[0]}:\n	Status from\
					 nmap: {obj_nmap[1]}\n	Status from ft_nmap: {obj_my_nmap[1]}{ANSI_COLOR_RESET}")
					print(f"{ANSI_COLOR_RED}FAILED{ANSI_COLOR_RESET}\n")
					return False
		# If lists differ in length or order, but no specific mismatch found in loop
		print(f"{ANSI_COLOR_RED}FAILED{ANSI_COLOR_RESET}\n")
		return False


if __name__ == '__main__':
	exit_code = subprocess.getstatusoutput("nmap --help")[0]
	if exit_code != 0:
		print(f"{ANSI_COLOR_RED}nmap not found{ANSI_COLOR_RESET}")
		sys.exit()
	exit_code = subprocess.getstatusoutput("./ft_nmap --help")[0]
	if exit_code != 0:
		print(f"{ANSI_COLOR_RED}ft_nmap executable not found{ANSI_COLOR_RESET}")
		sys.exit()
	target_ip = input("Enter the target IP address for tests: ")
	print(f"Testing against {target_ip}")
	passed = 0
	failed = 0
	print("Testing SYN scan...")
	if run_test(["nmap", target_ip, "-p", "1234-1244", "-sS"],
					["./ft_nmap", "--ip", target_ip, "--ports", "1234-1244", "--scan", "SYN"],
					"tcp"):
		passed += 1
	else:
		failed += 1
	print("Testing NULL scan...")
	if run_test(["nmap", target_ip, "-p", "1234-1244", "-sN"],
					["./ft_nmap", "--ip", target_ip, "--ports", "1234-1244", "--scan", "NULL"],
					"tcp"):
		passed += 1
	else:
		failed += 1
	print("Testing ACK scan...")
	if run_test(["nmap", target_ip, "-p", "1234-1244", "-sA"],
					["./ft_nmap", "--ip", target_ip, "--ports", "1234-1244", "--scan", "ACK"],
					"tcp"):
		passed += 1
	else:
		failed += 1
	print("Testing FIN scan...")
	if run_test(["nmap", target_ip, "-p", "1234-1244", "-sF"],
					["./ft_nmap", "--ip", target_ip, "--ports", "1234-1244", "--scan", "FIN"],
					"tcp"):
		passed += 1
	else:
		failed += 1
	print("Testing XMAS scan...")
	if run_test(["nmap", target_ip, "-p", "1234-1244", "-sX"],
					["./ft_nmap", "--ip", target_ip, "--ports", "1234-1244", "--scan", "XMAS"],
					"tcp"):
		passed += 1
	else:
		failed += 1
	print("Testing UDP scan...")
	if run_test(["nmap", target_ip, "-p", "1234-1244", "-sU"],
					["./ft_nmap", "--ip", target_ip, "--ports", "1234-1244", "--scan", "UDP"],
					"udp"):
		passed += 1
	else:
		failed += 1
	print("Testing SYN scan on ports 22-30...")
	if run_test(["nmap", target_ip, "-p", "22-30", "-sS"],
					["./ft_nmap", "--ip", target_ip, "--ports", "22-30", "--scan", "SYN"],
					"tcp"):
		passed += 1
	else:
		failed += 1
	print("Testing SYN scan on single port 80...")
	if run_test(["nmap", target_ip, "-p", "80", "-sS"],
					["./ft_nmap", "--ip", target_ip, "--ports", "80", "--scan", "SYN"],
					"tcp"):
		passed += 1
	else:
		failed += 1
	print("Testing multiple scans SYN and ACK...")
	if run_test(["nmap", target_ip, "-p", "22-25", "-sS", "-sA"],
					["./ft_nmap", "--ip", target_ip, "--ports", "22-25", "--scan", "SYN,ACK"],
					"tcp"):
		passed += 1
	else:
		failed += 1
	print(f"\nTest Summary:")
	print(f"{ANSI_COLOR_GREEN}Passed: {passed}{ANSI_COLOR_RESET}")
	print(f"{ANSI_COLOR_RED}Failed: {failed}{ANSI_COLOR_RESET}")
	print(f"Total: {passed + failed}")