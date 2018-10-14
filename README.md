# Invisi-Shell
Hide your powershell script in plain sight! Invisi-Shell bypasses all of Powershell security features (ScriptBlock logging, Module logging, Transcription, AMSI) by hooking .Net assemblies. The hook is performed via CLR Profiler API.

# Work In Progress
This is still a preliminary version intended as a POC. The code works only on x64 processes and tested against Powershell V5.1.

# Compilation
Project was created with Visual Studio 2013. You should install Windows Platform SDK to compile it properly.

# Detailed Description
More info can be found on the [DerbyCon presentation](http://www.irongeek.com/i.php?page=videos/derbycon8/track-3-15-goodbye-obfuscation-hello-invisi-shell-hiding-your-powershell-script-in-plain-sight-omer-yair) by Omer Yair (October, 2018).

# Credits
 - CorProfiler by .NET Foundation
 - Eyal Ne'emany
 - Guy Franco
 - Ephraim Neuberger
 - Yossi Sassi
 - Omer Yair
