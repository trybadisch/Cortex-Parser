findings = {
	"AgentPassword": {
		"Name": "Agent Password Hash",
		"Desc": "",
		"PasswordSalt": "",
		"PasswordHash": ""
	},
	"FileTypeExecutable": {
		"Name": "Portable Executables",
		"Desc": "Path whitelist for PE execution.",
		"Enabled": "",
		"Paths": []
	},
	"FileTypeDll": {
		"Name": "Dynamic Link Libraries",
		"Desc": "Path whitelist for DLL execution.",
		"Enabled": "",
		"Paths": []
	},
	"FileTypeOfficeDocs": {
		"Name": "Office Macros",
		"Desc": "Path whitelist for Macro execution.",
		"Enabled": "",
		"Paths": []
	},
	"whitelistSigners": {
		"Name": "Whitelisted Signers",
		"Desc": "Execution whitelist by software signer.",
		"Mode": "",
		"Signers": [],
		"Paths": []
	},
	"webshellDroppers": {
		"Name": "Webshell Droppers",
		"Desc": "",
		"Mode": "",
		"Paths": []
	},
	"dynamicSecurityEngine": {
		"Name": "Dynamic Security Engine",
		"Desc": "Path whitelist for LOLBAS activity.",
		"Mode": "",
		"Paths": []
	},
	"scanEndpoints": {
		"Name": "Endpoints Scan",
		"Desc": "External drive scanning path exclusions.",
		"Mode": "",
		"Paths": []
	},
	"legitimateProcesses": {
		"Name": "Legitimate Processes",
		"Desc": "Parent process whitelist: excludes its child processes from analysis.",
		"Mode": "",
		"Processes": []
	},
	"Publishers": {
		"Name": "Trusted Publishers",
		"Desc": "Execution whitelist by software publisher.",
		"TrustedPublishers": [],
		"UserPublishers": []
	},
	"examineScriptFiles": {
		"Name": "Script Files",
		"Desc": "",
		"Mode": "",
		"Languages": {}
	},
	
	"passwordStealing": {
		"Name": "Credential Gathering",
		"Desc": "Path whitelist for processes accessing credentials.",
		"Mode": "",
		"Paths": []
	},
	"passwordTheftProtection": {
		"Name": "Memory Protection",
		"Desc": "Status of the module that monitors memory access.",
		"Mode": ""
	},
	
	"ransomware": {
		"Name": "Ransomware Protection",
		"Desc": "",
		"Mode": "",
		"Settings": {}
	},
	
	# Other FileTypes
	"FileTypeBatchScript": { "Name": "Batch Scripts", "Enabled": "", "Paths": [] },
	"FileTypeDotnetExecutable": { "Name": "Dotnet Executables", "Enabled": "", "Paths": [] },
	"FileTypeJavaScript": { "Name": "JavaScripts", "Enabled": "", "Paths": [] },
	"FileTypeMshta": { "Name": "Mshtas", "Enabled": "", "Paths": [] },
	"FileTypePdf": { "Name": "PFDs", "Enabled": "", "Paths": [] },
	"FileTypePowerShell": { "Name": "PowerShells", "Enabled": "", "Paths": [] },
	"FileTypeVBScript": { "Name": "VBScripts", "Enabled": "", "Paths": [] },
}
