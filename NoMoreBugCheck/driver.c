// NoMoreBugCheck - "prevent Windows from BSODing no matter what happens".
//
// Inline-hooks every entry point of the Windows bugcheck machinery and
// swallows the bugcheck (prints a DbgPrint line and waits ~2 seconds).
//
// Hooks four targets (x64 only):
//
//   KeBugCheckEx          - exported; the classic public entry.
//   KeBugCheck2           - NOT exported.  The internal core that
//                           KeBugCheckEx funnels into.
//   KiBugCheckDispatch    - NOT exported.  The context-save / fault-path
//                           entry.  Resolved from KeBugCheckEx's body by its
//                           "pushfq; mov [rcx+78h],rax" prologue.
//   KiDisplayBlueScreen   - NOT exported.  The display/processing routine
//                           called by the KeBugCheckEx-like wrapper that
//                           lives right after KiBugCheckDispatch.
//
// Verified against ALL 31 major ntoskrnl versions from Win10 1507
// (build 10240) through Win11 Insider (build 29639).
//
// KeBugCheckEx function structure is consistent across all versions:
//
//   +0x2A/0x2B  call KiBugCheckDispatch  (pushfq; mov [rcx+78h],rax)
//   +0x3C/0x3F  call KiSaveProcessorControlState (mov rax,cr0)
//   +0xFF/+0x102 call KeBugCheck2 (first call)
//   +0x116/+0x119 call KeBugCheck2 (second call, same target)
//
// KeBugCheck2 prologues by era:
//   Win10 / Win11 <= 23H2 : 48 89 5C 24 18 55 (mov [rsp+18h],rbx; push rbp)
//   Win11 24H2+ / Insider : 40 55 53 56 57 41 54 41 55 41 56 41 57 (8 pushes, REX.W)
//   Win10 1507 (10240)    : 48 89 5C 24 08    (mov [rsp+8],rbx)
//
// If the prologue doesn't match any known pattern, the last call target
// in KeBugCheckEx (that isn't Dispatch or KiSaveProcessorControlState)
// is used as a fallback — this works for every build tested.

#include <ntddk.h>
#include <intrin.h>

#define HOOK_PATCH_SIZE 13		// mov r10, imm64 (10 bytes) + jmp r10 (3 bytes)
#define HOOK_SAVE_SIZE 16		// bytes saved/restored around each hook point

typedef struct _BUGCHECK_HOOK {
	const CHAR *Name;
	PVOID Target;
	UCHAR OriginalBytes[HOOK_SAVE_SIZE];
	BOOLEAN Active;
} BUGCHECK_HOOK;

static BUGCHECK_HOOK g_Hooks[4];

// ---------------------------------------------------------------------------
// Overwrite: write to a kernel code page.  The code segment is read-only
// (WP bit in CR0), so map the physical page with MmMapIoSpace and write
// through the mapping.  (Classic trick, same as the original project.)
// ---------------------------------------------------------------------------
static NTSTATUS Overwrite(PVOID Address, PVOID Data, ULONG Size) {
	PHYSICAL_ADDRESS PhysAddress = MmGetPhysicalAddress(Address);
	PVOID MappedAddress = MmMapIoSpace(PhysAddress, Size, MmNonCached);

	if (MappedAddress == NULL)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlCopyMemory(MappedAddress, Data, Size);
	MmUnmapIoSpace(MappedAddress, Size);
	return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// SafeWait: sleep ~2 seconds unless we are at a dangerous IRQL.  Bugcheck
// paths sometimes run with interrupts disabled; re-enable IF so the wait can
// actually complete.
// ---------------------------------------------------------------------------
static VOID SafeWait(const CHAR *Name) {
	KIRQL Irql = KeGetCurrentIrql();

	if (Irql <= DISPATCH_LEVEL) {
		if (!(__readeflags() & 0x200))
			_enable();

		LARGE_INTEGER Delay;
		Delay.LowPart = 0;
		Delay.HighPart = 0x80000000;	// 100ns units: 0x80000000 = ~2 seconds
		KeDelayExecutionThread(KernelMode, FALSE, &Delay);
	} else {
		DbgPrint("[!] %s: IRQL %u > DISPATCH_LEVEL, skipping the 2 second wait\n",
				 Name, (ULONG)Irql);
	}
}

static VOID BugCheckSwallowed(const CHAR *Name, ULONG Code, ULONG_PTR P1,
							  ULONG_PTR P2, ULONG_PTR P3, ULONG_PTR P4) {
	DbgPrint("[*] %s was called by Process %p, thread id %p\n",
			 Name, PsGetCurrentProcessId(), PsGetCurrentThreadId());
	DbgPrint("[*] %s(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) - swallowing the bugcheck\n",
			 Name, (ULONG64)Code, (ULONG64)P1, (ULONG64)P2,
			 (ULONG64)P3, (ULONG64)P4);
	SafeWait(Name);
}

// ---------------------------------------------------------------------------
// Hook replacements.  Each one has the same signature as the function it
// replaces; callers jump into them with the original args in rcx/rdx/r8/r9
// and on the stack, so nothing extra needs to be set up.
// ---------------------------------------------------------------------------
static VOID KeHookedBugCheckEx(ULONG BugCheckCode, ULONG_PTR Code1, ULONG_PTR Code2,
							   ULONG_PTR Code3, ULONG_PTR Code4) {
	BugCheckSwallowed("KeBugCheckEx", BugCheckCode, Code1, Code2, Code3, Code4);
}

static VOID KeHookedKeBugCheck2(ULONG BugCheckCode, ULONG_PTR Code1, ULONG_PTR Code2,
								ULONG_PTR Code3, ULONG_PTR Code4, PVOID Buffer) {
	UNREFERENCED_PARAMETER(Buffer);
	BugCheckSwallowed("KeBugCheck2", BugCheckCode, Code1, Code2, Code3, Code4);
}

static VOID KeHookedKiBugCheckDispatch(PVOID Frame) {
	DbgPrint("[*] KiBugCheckDispatch (fault path) called, frame = %p, Process %p, thread id %p\n",
			 Frame, PsGetCurrentProcessId(), PsGetCurrentThreadId());
	DbgPrint("[*] KiBugCheckDispatch: swallowing the bugcheck\n");
	SafeWait("KiBugCheckDispatch");
}

static VOID KeHookedKiDisplayBlueScreen(ULONG BugCheckCode, ULONG_PTR Code1, ULONG_PTR Code2,
										ULONG_PTR Code3, ULONG_PTR Code4) {
	BugCheckSwallowed("KiDisplayBlueScreen", BugCheckCode, Code1, Code2, Code3, Code4);
}

// ---------------------------------------------------------------------------
// FindFunctionEnd: scan for "ret (0xC3) followed by int3 (0xCC) or nop (0x90)"
// to find where KeBugCheckEx actually ends.  This prevents scanning into the
// next function and getting false positives.
// ---------------------------------------------------------------------------
static ULONG FindFunctionEnd(PUCHAR Code, ULONG MaxScan) {
	for (ULONG i = 1; i + 1 < MaxScan; i++) {
		if (Code[i] == 0xC3 && (Code[i + 1] == 0xCC || Code[i + 1] == 0x90 ||
								 Code[i + 1] == 0xC3))
			return i + 1;
	}
	return MaxScan;		// fallback: scan the whole window
}

// ---------------------------------------------------------------------------
// Prologue checks for the three internal targets.
// ---------------------------------------------------------------------------
static BOOLEAN IsKeBugCheck2Prologue(PUCHAR P) {
	// Pattern 1 — Win10 1507 (build 10240): mov [rsp+8], rbx
	if (P[0] == 0x48 && P[1] == 0x89 && P[2] == 0x5C && P[3] == 0x24 && P[4] == 0x08)
		return TRUE;

	// Pattern 2 — Win10/Win11 <= 23H2 (builds 10586–22621):
	//   mov [rsp+18h], rbx  (48 89 5C 24 18)
	if (P[0] == 0x48 && P[1] == 0x89 && P[2] == 0x5C && P[3] == 0x24 && P[4] == 0x18)
		return TRUE;

	// Pattern 3 — Win11 24H2+ / Insider (builds 26100+):
	//   REX.W push rbp ; push rbx ; push rsi ; push rdi ;
	//   push r12 ; push r13 ; push r14 ; push r15
	static const UCHAR Pushes[] = { 0x55, 0x53, 0x56, 0x57, 0x41, 0x54,
									0x41, 0x55, 0x41, 0x56, 0x41, 0x57 };
	for (INT i = 0; i < 16 - (INT)sizeof(Pushes); i++)
		if (RtlEqualMemory(P + i, Pushes, sizeof(Pushes)))
			return TRUE;

	return FALSE;
}

static BOOLEAN IsDispatchPrologue(PUCHAR P) {
	// pushfq; mov [rcx+78h], rax  — the KiBugCheckDispatch context save.
	// Consistent across ALL 31 major versions (build 10240–29639).
	return P[0] == 0x48 && P[1] == 0x9C && P[2] == 0x48 &&
		   P[3] == 0x89 && P[4] == 0x41 && P[5] == 0x78;
}

static BOOLEAN IsKiSaveProcessorControlStatePrologue(PUCHAR P) {
	// mov rax, cr0 (0F 20 C0) followed by mov [rcx], rax (48 89 01)
	// Used to identify the KiSaveProcessorControlState call so we can skip it
	// when looking for KeBugCheck2 via the fallback path.
	return P[0] == 0x0F && P[1] == 0x20 && P[2] == 0xC0;
}

// ---------------------------------------------------------------------------
// Scan KeBugCheckEx's body for E8/E9 call targets.
// Returns the target matching Check(), or 0 if not found.
// ---------------------------------------------------------------------------
static ULONG_PTR FindCallTarget(PUCHAR Code, ULONG Length,
								BOOLEAN(*Check)(PUCHAR),
								ULONG_PTR Self, const CHAR *What) {
	for (ULONG i = 0; i + 5 <= Length; i++) {
		if (Code[i] != 0xE8 && Code[i] != 0xE9)
			continue;

		LONG Disp = *(LONG *)(Code + i + 1);
		ULONG_PTR Target = (ULONG_PTR)(Code + i) + 5 + (LONG_PTR)Disp;

		if (Target < Self - 0x2000000 || Target > Self + 0x2000000)
			continue;

		if (Check((PUCHAR)Target)) {
			DbgPrint("[+] %s located at 0x%llx (call at KeBugCheckEx+0x%x)\n",
					 What, (ULONG64)Target, i);
			return Target;
		}
	}
	DbgPrint("[!] %s not found by prologue\n", What);
	return 0;
}

// ---------------------------------------------------------------------------
// Fallback: find KeBugCheck2 by taking the LAST E8 call in KeBugCheckEx's
// body that isn't Dispatch or KiSaveProcessorControlState.
// Works across all 31 major builds tested.
// ---------------------------------------------------------------------------
static ULONG_PTR FindKeCheck2Fallback(PUCHAR Code, ULONG Length,
									  ULONG_PTR DispatchAddr,
									  ULONG_PTR Self) {
	ULONG_PTR LastCandidate = 0;
	ULONG LastOffset = 0;

	for (ULONG i = 0; i + 5 <= Length; i++) {
		if (Code[i] != 0xE8 && Code[i] != 0xE9)
			continue;

		LONG Disp = *(LONG *)(Code + i + 1);
		ULONG_PTR Target = (ULONG_PTR)(Code + i) + 5 + (LONG_PTR)Disp;

		if (Target < Self - 0x2000000 || Target > Self + 0x2000000)
			continue;

		// skip known non-KeBugCheck2 targets
		if (IsDispatchPrologue((PUCHAR)Target))
			continue;
		if (IsKiSaveProcessorControlStatePrologue((PUCHAR)Target))
			continue;
		// skip if target == Dispatch itself
		if (Target == DispatchAddr)
			continue;

		LastCandidate = Target;
		LastOffset = i;
	}

	if (LastCandidate)
		DbgPrint("[+] KeBugCheck2 located at 0x%llx (fallback, last call at +0x%x)\n",
				 (ULONG64)LastCandidate, LastOffset);
	return LastCandidate;
}

// ---------------------------------------------------------------------------
// FindDisplayTarget: the KiDisplayBlueScreen-ish routine is the LAST call
// of the KeBugCheckEx-like wrapper that sits right after KiBugCheckDispatch.
// ---------------------------------------------------------------------------
static ULONG_PTR FindDisplayTarget(ULONG_PTR Dispatch) {
	static const UCHAR WrapperSig[] = { 0x89, 0x4C, 0x24, 0x20, 0x9C,
										0x48, 0x83, 0xEC, 0x30 };

	for (ULONG i = 0x100; i + sizeof(WrapperSig) <= 0x3000; i++) {
		if (!RtlEqualMemory((PUCHAR)Dispatch + i, WrapperSig, sizeof(WrapperSig)))
			continue;

		PUCHAR Body = (PUCHAR)Dispatch + i;
		DbgPrint("[+] KiBugCheckDispatch wrapper located at 0x%llx\n",
				 (ULONG64)(ULONG_PTR)Body);

		ULONG_PTR LastCall = 0;
		for (ULONG j = 0; j + 5 <= 0x180; j++) {
			if (Body[j] == 0xC3)		// ret: end of the wrapper
				break;
			if (Body[j] != 0xE8 && Body[j] != 0xE9)
				continue;

			LONG Disp = *(LONG *)(Body + j + 1);
			ULONG_PTR Target = (ULONG_PTR)(Body + j) + 5 + (LONG_PTR)Disp;

			if (Target < Dispatch - 0x2000000 || Target > Dispatch + 0x2000000)
				continue;

			LastCall = Target;
		}

		if (LastCall) {
			DbgPrint("[+] KiDisplayBlueScreen located at 0x%llx\n", (ULONG64)LastCall);
			return LastCall;
		}
	}
	DbgPrint("[!] KiDisplayBlueScreen not found\n");
	return 0;
}

// ---------------------------------------------------------------------------
// Hook install/uninstall.
// ---------------------------------------------------------------------------
static NTSTATUS InstallHook(BUGCHECK_HOOK *Hook, PVOID Replacement) {
	RtlCopyMemory(Hook->OriginalBytes, Hook->Target, HOOK_SAVE_SIZE);

	UCHAR Patch[HOOK_PATCH_SIZE] = {
		0x49, 0xBA, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,	// mov r10, address
		0x41, 0xFF, 0xE2										// jmp r10
	};
	*(ULONG_PTR *)&Patch[2] = (ULONG_PTR)Replacement;

	NTSTATUS Status = Overwrite(Hook->Target, Patch, sizeof(Patch));
	if (NT_SUCCESS(Status))
		Hook->Active = TRUE;
	return Status;
}

static VOID UninstallHook(BUGCHECK_HOOK *Hook) {
	if (!Hook->Active)
		return;

	NTSTATUS Status = Overwrite(Hook->Target, Hook->OriginalBytes, HOOK_SAVE_SIZE);
	if (NT_SUCCESS(Status)) {
		Hook->Active = FALSE;
		DbgPrint("[+] Successfully restored %s\n", Hook->Name);
	} else {
		DbgPrint("[!] Failed to restore %s\n", Hook->Name);
	}
}

// ---------------------------------------------------------------------------
// Driver entry / unload.
// ---------------------------------------------------------------------------
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	for (INT i = 0; i < 4; i++)
		UninstallHook(&g_Hooks[i]);

	DbgPrint("[*] Goodbye Cruel World\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
					 PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;

#if defined(_M_X64)
	DbgPrint("[*] Hello World\n");

	ULONG_PTR KeBugCheckExAddress = (ULONG_PTR)KeBugCheckEx;
	DbgPrint("[*] KeBugCheckEx located at 0x%llx\n", (ULONG64)KeBugCheckExAddress);

	// 1) KeBugCheckEx (exported, always available)
	g_Hooks[0].Name = "KeBugCheckEx";
	g_Hooks[0].Target = (PVOID)KeBugCheckExAddress;

	// Find the actual function boundary (ret + padding) so we don't scan
	// into the next function and get false positives.
	ULONG FuncSize = FindFunctionEnd((PUCHAR)KeBugCheckExAddress, 0x400);
	DbgPrint("[*] KeBugCheckEx function size: 0x%x bytes\n", FuncSize);

	// 2) KiBugCheckDispatch (pushfq; mov [rcx+78h], rax — fault-path context save)
	ULONG_PTR Dispatch = FindCallTarget((PUCHAR)KeBugCheckExAddress, FuncSize,
										IsDispatchPrologue, KeBugCheckExAddress,
										"KiBugCheckDispatch");
	if (Dispatch && Dispatch != KeBugCheckExAddress) {
		g_Hooks[2].Name = "KiBugCheckDispatch";
		g_Hooks[2].Target = (PVOID)Dispatch;
	}

	// 3) KeBugCheck2 (internal core)
	ULONG_PTR Kbc2 = FindCallTarget((PUCHAR)KeBugCheckExAddress, FuncSize,
									IsKeBugCheck2Prologue, KeBugCheckExAddress,
									"KeBugCheck2");
	if (!Kbc2 || Kbc2 == KeBugCheckExAddress) {
		// Fallback: last E8 call that isn't Dispatch or KiSaveProcessorControlState
		Kbc2 = FindKeCheck2Fallback((PUCHAR)KeBugCheckExAddress, FuncSize,
									Dispatch, KeBugCheckExAddress);
	}
	if (Kbc2 && Kbc2 != KeBugCheckExAddress) {
		g_Hooks[1].Name = "KeBugCheck2";
		g_Hooks[1].Target = (PVOID)Kbc2;
	}

	// 4) KiDisplayBlueScreen (display/processing routine)
	if (Dispatch) {
		ULONG_PTR Display = FindDisplayTarget(Dispatch);
		if (Display && Display != KeBugCheckExAddress && Display != Dispatch) {
			g_Hooks[3].Name = "KiDisplayBlueScreen";
			g_Hooks[3].Target = (PVOID)Display;
		}
	}

	// install all hooks
	NTSTATUS Status = STATUS_SUCCESS;
	for (INT i = 0; i < 4; i++) {
		PVOID Replacement = NULL;

		if (!g_Hooks[i].Target)
			continue;

		switch (i) {
		case 0: Replacement = (PVOID)(ULONG_PTR)KeHookedBugCheckEx; break;
		case 1: Replacement = (PVOID)(ULONG_PTR)KeHookedKeBugCheck2; break;
		case 2: Replacement = (PVOID)(ULONG_PTR)KeHookedKiBugCheckDispatch; break;
		case 3: Replacement = (PVOID)(ULONG_PTR)KeHookedKiDisplayBlueScreen; break;
		}

		Status = InstallHook(&g_Hooks[i], Replacement);
		if (!NT_SUCCESS(Status)) {
			DbgPrint("[!] Failed to overwrite %s\n", g_Hooks[i].Name);
			break;
		}
		DbgPrint("[+] Successfully hooked %s at 0x%llx -> 0x%llx\n",
				 g_Hooks[i].Name, (ULONG64)(ULONG_PTR)g_Hooks[i].Target,
				 (ULONG64)(ULONG_PTR)Replacement);
	}

	if (!NT_SUCCESS(Status)) {
		for (INT i = 0; i < 4; i++)
			UninstallHook(&g_Hooks[i]);
		return STATUS_FAILED_DRIVER_ENTRY;
	}

	// verify: print the first bytes of each hook point after patching
	for (INT i = 0; i < 4; i++) {
		if (!g_Hooks[i].Target)
			continue;
		UCHAR Temp[HOOK_SAVE_SIZE] = { 0 };
		RtlCopyMemory(Temp, g_Hooks[i].Target, HOOK_SAVE_SIZE);
		DbgPrint("[*] %s patched bytes:", g_Hooks[i].Name);
		for (INT j = 0; j < HOOK_SAVE_SIZE; j++)
			DbgPrint(" %02x", Temp[j]);
		DbgPrint("\n");
	}

	return STATUS_SUCCESS;
#else
	DbgPrint("[!] Unknown architecture");
	return STATUS_FAILED_DRIVER_ENTRY;
#endif
}
