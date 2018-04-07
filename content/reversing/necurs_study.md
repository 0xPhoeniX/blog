+++
title =  "Necurs Kit Privilege Escalation Study"
date = "2014-07-22T18:52:01-04:00"
slug = "necurs_study"
Tags = ["malware analysis", "exploitation", "necurs", "privilege escalation"]
Categories = ["Reversing"]
+++

Recently there were several new posts ([FSecure Post](http://www.f-secure.com/weblog/archives/00002717.html) and [Peter Ferrie](http://pferrie.host22.com/)) about updates to the Necurs malicious kit which in essence is based on the malicious driver with sole purpose to protect other malware from security products. The updated version is now shipped as an embedded self-contained launch-and-forget shellcode which will drop the appropriate driver according to the underlingg OS and on successful deployment will start immediate protection. The authors of the kit will supply the client several APIs that could be used to operate the driver.

I knew that for driver loading on OSs above Vista, it was using privilege escalation vulnerability. It was interesting to understand how that exploit was used in Necurs’ case and as I was unable to find a fine explanation, I studied it by myself . Here I present my findings for the matter.

### Deployment

As already mentioned, *Necurs* operates as a 3rd party driver – meaning, the user will need *Admin* rights to actually use it. Being a 3rd-party product, it needs to operate on verity of Windows OSs:

- Windows XP – by default the logged-in user is already *Admin*, so no problem here.
- Vista and above – the user will probably have UAC enabled which will prevent driver loading.

So, the solution for Vista and above was based on the [CVE-2010-4398](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4398) local privilege escalation vulnerability. It’s nicely explained in several places – by the [author](http://www.exploit-db.com/bypassing-uac-with-user-privilege-under-windows-vista7-mirror/) and [Peter Kleissner](http://stoned-vienna.com/html/index.php?page=advanced-analysis-of-the-2010-11-24-local-windows-kernel-exploit).

##### UAC By-Pass

The by-pass is based on changing the security token of the malicious process by the “powerful” one which is borrowed from the `system` process in kernel space. This task is achieved in the following way:

- **kernel APIs resolution** – as the exploit shellcode will actually be executed in the kernel space, it will need the appropriate API addresses to do so. Those APIs are resolved by extracting the APIs’ RVAs from the `ntoskrnl.exe` file and finding the actual `ntoskrnl.exe` base address (using `ZwQuerySystemInformation`).
- **registry preparation** – craft registry data in the way, that will trigger the [CVE-2010-4398](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4398) exploit as explained in the original [article](http://www.exploit-db.com/bypassing-uac-with-user-privilege-under-windows-vista7-mirror/) by calling `EnableEUDC`.
- **exploit shellcode execution** – get security token (`PsReferencePrimaryToken`) from the initial system process (`PsInitialSystemProcess`) and replace the current process’s (`IoGetCurrentProcess`) token with the new one (Fig. 1). Once token replaced, the shellcode will return to the original execution flow.

![](/images/necurs_necurs_token_replace.png)
<center>Figure 1: Grant Administrator privileges to current process</center>

Multi-OS support was achieved by using predefined offsets to the`Token` member in the `EPROCESS` structure (Fig 2).

![](/images/necurs_necurs_token_offset.png)
<center>Figure 2: Multi-OS support</center>

#### Return from exploit shellcode

Once the exploitation was done, the exploit shellcode will try to return to the original execution flow, as if nothing has happened (in other words, `internal_func_b` finished its execution properly – see below). For the explanation, I’ll use arbitrary symbolic addresses to describe the following call stack and 32 bit shellcode version:

<center>![](/images/necurs_stack.png)</center>

To understand the trick, let’s look how *ESP* changes from the call `EnableEUDC` till the stack overflow at `RtlQueryRegistryValues`. The overflow will overwrite the return address of `internal_func_b` (for explanation please read [here](http://stoned-vienna.com/html/index.php?page=advanced-analysis-of-the-2010-11-24-local-windows-kernel-exploit)). *ESP* undergoes the following changes and this “picture” of *ESP* is what exploit shellcode will see (Fig 3):

<center>

|  **ESP address**    |   **ESP pointed data**   |   **Remarks**   |
| :--: | :--: | :--: |
| 0x0 | 1 | parameter for `EnableEUDC` |
| 0x4 | 0xae1efe | return after `EnableEUDC` |
| 0x8 | shellcode EBP | EIP is currently in `GreEnableEUDC` |
| 0xC | param 1 |      |
| 0x10 | param 2 |      |
| 0x14 | 0xbf81b8d0 | return after call to `internal_func_a` |
| 0x18 | internal_func_a EBP |      |
| 0x3C | local vars | local params in `internal_func_a` |
| 0x40 | reg value |      |
| 0x44 | reg value |      |
| 0x48 | reg value | this is what exploit shellcode sees |

</center>

![](/images/necurs_shellcode_return.png)
<center>Figure 3: Return from exploit shellcode</center>

The `token_fix` global variable will fix the *ESP* in a such way, so it will point to the `internal_func_a stack` frame. Finally, the return address of `internal_func_a` is used to return to the original flow of execution (Fig 4).

![](/images/necurs_find_ret_address.png)
<center>Figure 4: Searching for return address</center>

Once found, the flow will land in `internal_func_a` (Fig 5).

![](/images/necurs_execution_continue.png)
<center>Figure 5: Execution after exploitation</center>

Now, the running process has *Administrator* account rights, so the only simple thing left is just to re-launch itself, drop and load the driver. Just to note, that on 64 bit systems, there are similar flow of events occur.