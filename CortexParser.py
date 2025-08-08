import sys
import plyvel
import json
from termcolor import colored

from finding_dict import findings

# Read directory containing LevelDB
def read_leveldb(path):
	'''
	policyRaw.Settings = Contains most whitelists exceptions:
		FileTypeBatchScript, FileTypeDll, FileTypeDotnetExecutable, FileTypeExecutable, FileTypeJavaScript, FileTypeMshta,
			FileTypeOfficeDocs, FileTypePdf, FileTypePowerShell, FileTypeVBScript
		PasswordHash, PasswordSalt
		TrustedPublishers, UserPublishers

	settings = Python memory dump, contains:
	.mpm = Contains scanEndpoints, webshellDroppers, examineOfficeFiles, examineScriptFiles, legitimateProcesses,
		dynamicSecurityEngine, and PE whitelistSigners (examinePortableExecutables)
	.agset = Contains uninstallPasswordHardened (hex)
	'''
	try:
		db = plyvel.DB(path, create_if_missing=False)
		policy = db.get(b'policyRaw').decode('utf-8', errors='ignore')
		settings = db.get(b'settings').decode('utf-8', errors='ignore')
		db.close()
	except plyvel._plyvel.Error:
		sys.exit("Error: \""+path+"\" is not a valid Database Lock directory.")

	policy = json.loads(policy[policy.index('{'):])
	d_settings = decode_settings(settings)
	
	return policy, d_settings

# Finds every JSON in memory dump (settings) DB blob
def decode_settings(settings, d_settings={}, pos=0, decoder=json.JSONDecoder()):
	first = settings[pos:].index('{')+pos
	try:
		obj, last = decoder.raw_decode(settings, first)
		d_settings.update(obj)
		decode_settings(settings, d_settings, last)
	except Exception as e:
		if "Expecting property name enclosed in double quotes" in str(e):
			decode_settings(settings, d_settings, first+1)
		else:
			pass
	return d_settings

# Get values from policy DB
def get_policy_values(policy):
	findings["AgentPassword"]["PasswordSalt"] = policy["PasswordSalt"]
	findings["AgentPassword"]["PasswordHash"] = policy["PasswordHash"]
	findings["Publishers"]["TrustedPublishers"] = policy["TrustedPublishers"]
	findings["Publishers"]["UserPublishers"] = policy["UserPublishers"]
	for f_type in findings:
		if "FileType" in f_type:
			findings[f_type]["Enabled"] = policy[f_type]["Enable"]
			findings[f_type]["Paths"] = policy[f_type]["PathWhiteList"]
	return

# Get values from settings DB
def get_settings_values(settings):
	for s_type in settings:
		if s_type["type"] in ["scanEndpoints", "webshellDroppers", "dynamicSecurityEngine", "passwordStealing"]:
			findings[s_type["type"]]["Mode"] = s_type["mode"]
			findings[s_type["type"]]["Paths"] = s_type["settings"]["whitelistFolders"]
		
		if s_type["type"] == "examinePortableExecutables":
			findings["whitelistSigners"]["Mode"] = s_type["mode"]
			findings["whitelistSigners"]["Signers"] = s_type["settings"]["whitelistSigners"]
			findings["whitelistSigners"]["Paths"] = s_type["settings"]["whitelistFolders"]
		
		if s_type["type"] == "legitimateProcesses":
			findings["legitimateProcesses"]["Mode"] = s_type["mode"]
			findings["legitimateProcesses"]["Processes"] = s_type["settings"]["allow"]
		
		if s_type["type"] == "examineScriptFiles":
			findings["examineScriptFiles"]["Mode"] = s_type["mode"]
			for lang in s_type["settings"]:
				findings["examineScriptFiles"]["Languages"][lang] = s_type["settings"][lang]["settings"]["whitelistFolders"]
		
		if s_type["type"] == "passwordTheftProtection":
			findings["passwordTheftProtection"]["Mode"] = s_type["mode"]
		
		if s_type["type"] == "ransomware":
			findings["ransomware"]["Mode"] = s_type["mode"]
			findings["ransomware"]["Settings"] = s_type["settings"]
	return		

# Print results. Categories are shown only if relevant info is found
def print_results(findings):	
	banner ='''\
   ______           __               ____                           
  / ____/___  _____/ /____  _  __   / __ \____ ______________  _____
 / /   / __ \/ ___/ __/ _ \| |/_/  / /_/ / __ `/ ___/ ___/ _ \/ ___/
/ /___/ /_/ / /  / /_/  __/>  <   / ____/ /_/ / /  (__  )  __/ /    
\____/\____/_/   \__/\___/_/|_|  /_/    \__,_/_/  /____/\___/_/     
'''
	print(colored(banner, "green", attrs=["bold"]))

	for k,v in findings.items():
		# if k not in other_filetypes:
		if "Paths" in v.keys() and len(v["Paths"]) == 0 and \
		("Enabled" in v.keys() and v["Enabled"] == False or \
		"Mode" in v.keys() and v["Mode"] == "disabled"):
			continue

		elif "Processes" in v.keys() and len(v["Processes"]) == 0:
			continue
		elif "Languages" in v.keys():
			lang_sum = sum([len(l_v) for l_k,l_v in v["Languages"].items()])
			if lang_sum == 0:	
				continue
				
		else:
			print(colored("[*] ", attrs=["bold"]) + colored(findings[k]["Name"], "green", attrs=["bold"]))
			if "Desc" in v.keys() and len(v["Desc"]) != 0:
				print(findings[k]["Desc"])
			print()
		
		if k == "AgentPassword":
			print("PasswordHash: " + colored(v["PasswordHash"], "red"))
			print("PasswordSalt: " + colored(v["PasswordSalt"], "red"))
		
		if k == "Publishers":
			print("TrustedPublishers:\n " + colored('\n '.join(v["TrustedPublishers"]), "red"))
			print("UserPublishers:\n " + colored('\n '.join(v["UserPublishers"]), "red"))
		
		if "Enabled" in v.keys():
			print("Enabled: " + colored(v["Enabled"], "red"))
		if "Mode" in v.keys():
			print("Mode: " + colored(v["Mode"], "red"))
		if "Settings" in v.keys():
			print("Settings:")
			for s_k,s_v in v["Settings"].items():
				print(" " + s_k + ": " + colored(s_v, "red"))
		
		if "Signers" in v.keys():
			print("Signers:\n " + colored('\n '.join(v["Signers"]), "red"))
		if "Languages" in v.keys():
			for l_k,l_v in v["Languages"].items():
				print(" " + l_k + ": " + colored(l_v, "red"))
		
		if "Paths" in v.keys():
			if len(v["Paths"]) != 0:
				print("Paths:\n " + colored('\n '.join(v["Paths"]), "red"))
			else:
				print("Paths: " + colored("No whitelisted paths", "green"))
		
		print()

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print("Usage: "+sys.argv[0]+" [LDB_Files]")
		print('''\nDatabase Lock files are located in C:\\ProgramData\\Cyvera\\LocalSystem\\Persistence\\agent_settings.db,\
 and must be accessed with elevated privileges.''')
		print("\nThe path containing these files must be used as an argument:")
		print(" *.ldb  CURRENT  LOCK  LOG  LOG.OLD  MANIFEST-*")
		sys.exit()

	path = sys.argv[1]
	policy, settings = read_leveldb(path)
	policy = get_policy_values(policy["Settings"])
	settings = get_settings_values(settings["mpm"])
	print_results(findings)
	
	# print(json.dumps(findings))
