# RedTeamCCode
Red Team C code repo

# PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON.c

Is a proof-of-concept for the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` trick it will enforce the policy then spawn itself again the respawned process have the policy enforced allowing you run "malicious" code with the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` been set.

# byebyedll.c

Is a proof-of-concept that enforce the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` policy and also debug the child process (itself) and monitor Dlls that are loaded using Windows debugger APIs. It detect Dlls based on the path and patch it. The idea is to prevent EDR and AV Dlls loaded into your process from executing properly. This is a POC the blacklisted Dlls is set to `user32.dll`.  

# Credit 
Mr.Un1k0d3r RingZer0 Team
