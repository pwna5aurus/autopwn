# autopwn
Domain AutoPwn v1.0

By Ben Floyd (def.jammin@gmail.com)
Available under the BSD-3 Clause

Summary:

   This is a bot, which uses a number of tools, including PowerSploit's Recon module, PAExec, and Mimikatz,
   searches for machines where the current Domain User account has local admin rights and grabs credentials, 
   and automatically elevates itself to Domain Admin, if a path exists between current credentials and a DA account.
   If not, it switches to the next found user and repeats.

   It is able to check all Domain User accounts recovered for workstations/servers where they have local admin rights,
   to obtain further credentials and pivot/escalate.  

   As Powershell is not always remotely enabled, this script can enable it remotely with PAExec,
   which is decoded from a base64 string and invoked reflectively in memory.

   When connected to a remote machine as local admin, it pulls Invoke-Mimikatz from the web (or a share,
   if necessary) and runs it in memory on the remote machine.

   All of the tools run from memory, evade anti-virus (tested against the current iteration of Symantec Endpoint Protection 12.1.6,
   as of time of writing), and leave no trace.  Logs are optional.

   It is intended to locate cached credentials within a domain and find Elevation of Privilege (EoP)
   paths.  It is meant to audit highly privileged (domain admin) accounts and quickly locate possible paths.
   
   I wrote this software for the purposes of pentesting.  There are many great components/modules/tools out there, written by talented 
   people.  But this is for the (extremely) busy/lazy.....after you have obtained, perhaps, helpdesk or service account credentials.  Often 
   in a penetration testing engagement, you are pressed for time and need to pwn the domain quickly to give your client the best value.
   This will do the trick, but keep in mind, this tool does not come with a "rules of engagement" or "scope" feature...yet.
   
   
   Use of this software for malicious purposes is EXPRESSLY PROHIBITED.
   
   
   
   In future revisions, I may add the capability to find the shortest distance between current Domain User and Domain Admin.
   
   
   
   
   
PowerSploit is provided under the 3-clause BSD license below:
Copyright (c) 2012, Matthew Graeber
All rights reserved.


Mimikatz is a program originally written by Benjamin Delpy
https://github.com/gentilkiwi/mimikatz

PAExec is made by the awesome folks at https://www.poweradmin.com/paexec/
