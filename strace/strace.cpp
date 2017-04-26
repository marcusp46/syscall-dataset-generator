/*BEGIN_LEGAL
Intel Open Source License
Copyright (c) 2002-2012 Intel Corporation. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */
/*
*  This file contains an ISA-portable PIN tool for tracing system calls
*/

/*TODO
create structure for 400 position array with 9-bit values indicated system calls called (short) INSTRUMENTATION FOR SPEED
create structure for 400*400 array with 4 and 2 bit values (KNOB parameter?) INSTRUMENTAION FOR SPEED

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#include <hash_map>
#include <iostream>
#include <string.h>
//#include <direct.h>

#include <vector>
#include "pin.H"
#include "syscall_win.h"
//#include <process.h>
//TODO....REPLACE with OS-API
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>


//#define _DEBUG 1
//#define _DEBUG_STRACE
//#define _CALLSTACK 1
//#define _CRT_SECURE_NO_WARNINGS 1

#undef BASE_HIST_ARRAY_SIZE
//#define BASE_HIST_ARRAY_SIZE 512000
#define BASE_HIST_ARRAY_SIZE 1250
#define NUM_THREADS 500
#define PR_MAX 256

#ifdef _DEBUG
#include "call-stack/call-stack.H"
#endif

void syscall_ntos(long num, char* dest);

FILE * trace;
FILE * trace2;
FILE * threads;
FILE * images;
FILE * children;
FILE * debug;
FILE * call_stack;
FILE * arrays;
FILE * summary;
FILE * array_dump;
FILE * psh_out;
FILE * context_out;
int ver_fd;

char logPath[1024], *main_exe;
int main_exe_iter = 0;


unsigned long long total_calls = 0;
unsigned long long total_win32k_calls = 0;
unsigned long long total_ntdll_calls = 0;
unsigned long long total_threads = 0;
PIN_LOCK lock;
PIN_LOCK lock_deleteme;
PIN_LOCK lock_sh;

syscall_adj_matrix **sam;
syscall_adj_matrix_bit **sam_bit;
syscall_hist psh;
syscall_hist context;
syscall_hist **tsh;
syscall_vec **sv;

char *thread_names;

static inline void add_item(syscall_hist *sh, unsigned short callno);
void init_hist(syscall_hist *sh);
VOID Fini(INT32 code, VOID *v);
VOID Start(VOID *v);
char* find_executable(int argc, char *argv[]);
int get_main_iter(char *logPath, char *base_name, int *ver_fd);
char* clean_hash_string(char *s);

// Print syscall number and arguments
VOID SysBefore(ADDRINT ip, ADDRINT num, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2, ADDRINT arg3, ADDRINT arg4, ADDRINT arg5, CONTEXT *ctxt, THREADID threadIndex)
{
	char dest[1024];
#ifdef _DEBUG
//	IMG root_image;
#endif
	string root_image_name, img_name;
	string callee_name;
//	static unsigned int array_blocks = 1;
//	unsigned char ntdll_sys = 0;

#if defined(TARGET_LINUX) && defined(TARGET_IA32) 
	// On ia32 Linux, there are only 5 registers for passing system call arguments, 
	// but mmap needs 6. For mmap on ia32, the first argument to the system call 
	// is a pointer to an array of the 6 arguments
	if (num == SYS_mmap)
	{
		ADDRINT * mmapArgs = reinterpret_cast<ADDRINT *>(arg0);
		arg0 = mmapArgs[0];
		arg1 = mmapArgs[1];
		arg2 = mmapArgs[2];
		arg3 = mmapArgs[3];
		arg4 = mmapArgs[4];
		arg5 = mmapArgs[5];
	}
#endif
	syscall_ntos((long)num, dest);

	//image = IMG_FindByAddress(ip);
	//img_name = IMG_Name(image);


	//#ifdef _DEBUG
	//		fprintf(debug,"BP: 0x%lx\n", PIN_GetContextReg(ctxt, REG_RBP) + 8/*, *(ADDRINT*)(PIN_GetContextReg(ctxt, REG_RBP) + 8)*/);
	//fprintf(debug, "RA: 0x%lx\n", PIN_GetContextReg(ctxt, REG_RBP) + 8, *(ADDRINT*)(PIN_GetContextReg(ctxt, REG_RBP) + 8));
	//#endif



	/*callee_name = *///IMG_Name(IMG_FindByAddress( *(ADDRINT*)(PIN_GetContextReg(ctxt, REG_RBP) + 8)));/* */
	//printf("BP: 0x%lx *BP: 0x%lx", PIN_GetContextReg(ctxt, REG_RBP) + 8), *(ADDRINT*)(PIN_GetContextReg(ctxt, REG_RBP) + 8));
	//flush(cout);

#ifdef _DEBUG
/*	CALLSTACK::CallStackManager *csm = CALLSTACK::CallStackManager::get_instance();
	CALLSTACK::CallStack cs = csm->get_stack(threadIndex);

	vector<string> v,bv;
	cs.emit_stack(4, v);
	cs.emit_bottom(bv);


	fprintf(debug, "THREAD: %u\n", threadIndex);
	for (unsigned int i = 0; i < v.size(); i++)
		fprintf(debug, "%s\n", v[i].c_str());
	for (unsigned int i = 0; i < bv.size(); i++)
		fprintf(debug, "%s\n", bv[i].c_str());
	root_image = IMG_FindByAddress(cs.bottom_target());
	root_image_name = IMG_Name(root_image);
	fprintf(debug, "FIRST %s THREAD %u IP=0x%lx %s TARGET=0x%lx %s\n",dest,threadIndex,cs.call_ip(),IMG_Name(IMG_FindByAddress(cs.call_ip())).c_str(),cs.bottom_target(),root_image_name.c_str());
*/
#endif


#ifdef _DEBUG_STRACE
	fprintf(trace, "0x%lx: %s %s %s0x%lx-%ld(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)",
		(unsigned long)ip,
		img_name.c_str(),
		dest,
		"test"/*callee_name.c_str()*/,
		(long)num,
		(long)num,
		(unsigned long)arg0,
		(unsigned long)arg1,
		(unsigned long)arg2,
		(unsigned long)arg3,
		(unsigned long)arg4,
		(unsigned long)arg5);
	fflush(trace);
#endif


	//TODO insert lock
	PIN_GetLock(&lock, threadIndex);
	if (num > 400 && num != 401 && num != NULL_SYS)
		total_win32k_calls++;
	else
	{
//		ntdll_sys = 1;
		total_ntdll_calls++;
	}

	total_calls++;

	if(arg0 == 15 && num == 157)
		strncpy((thread_names + threadIndex*PR_MAX),(char*)arg1,PR_MAX);

	/*
	if (ntdll_sys == 1){
		if (total_ntdll_calls == 1)
			syscall_history = (unsigned short int*)malloc(BASE_HIST_ARRAY_SIZE);
		else if (total_ntdll_calls % BASE_HIST_ARRAY_SIZE == 1)
		{
			array_blocks++;
			syscall_history = (unsigned short int*)realloc(syscall_history, BASE_HIST_ARRAY_SIZE*array_blocks);
		}

		*(syscall_history + total_ntdll_calls) = (unsigned short int)num;
	}
	*/
	PIN_ReleaseLock(&lock);
	//RELEASE lock
}
// Print the 	return value of the system call
VOID SysAfter(ADDRINT ret)
{
#ifdef _DEBUG_STRACE
	fprintf(trace, "returns: 0x%lx\n", (unsigned long)ret);
	fflush(trace);
#endif
}

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SysBefore(PIN_GetContextReg(ctxt, REG_INST_PTR),
		PIN_GetSyscallNumber(ctxt, std),
		PIN_GetSyscallArgument(ctxt, std, 0),
		PIN_GetSyscallArgument(ctxt, std, 1),
		PIN_GetSyscallArgument(ctxt, std, 2),
		PIN_GetSyscallArgument(ctxt, std, 3),
		PIN_GetSyscallArgument(ctxt, std, 4),
		PIN_GetSyscallArgument(ctxt, std, 5),
		ctxt,
		threadIndex);

	
}

VOID SyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, VOID *v)
{
	SysAfter(PIN_GetSyscallReturn(ctxt, std));
}

VOID PIN_FAST_ANALYSIS_CALL UpdateVector(THREADID id, ADDRINT num)
{
	//syscall_adj_matrix *sam;
	//syscall_adj_matrix_bit *sam;
	//syscall_vec *sv;
	ADDRINT previous;

	//fprintf(arrays, "ENTER\n");

/*	if ((*(sam + id))->prev_sys == NULL_SYS)
		previous = 401;
	else
		previous = (*(sam + id))->prev_sys;

	(*(sam + id))->array[previous][num]++;
	(*(sam + id))->count++;
	sam[id]->count++;
	(*(sam + id))->prev_sys = num;
*/
//	if(num >=56 && num <= 59)
//	PIN_GetLock(&lock_deleteme, id);
//		printf("execve class %ld - %s !!\n",num,main_exe);
//	PIN_ReleaseLock(&lock_deleteme);


	if (num > 400 && num != NULL_SYS && num != 401) 
		return;

	if (sam[id]->prev_sys == NULL_SYS)
		previous = 401;
	else
		previous = sam[id]->prev_sys;

	sam[id]->array[previous][num]++;
	sam[id]->count++;
	//sam[id]->count++;
	sam[id]->prev_sys = num;

	PIN_GetLock(&lock_sh, id);
	add_item(&psh,num);
	add_item(&context,(unsigned short)id);
	PIN_ReleaseLock(&lock_sh);

	add_item(tsh[id],num);

	//(*(sam_bit + id))->array[(*(sam_bit + id))->prev_sys][num] |= 1;

	//fprintf(arrays,"THREAD %u SYS 0x%lx\n",id,num);
	//fflush(arrays);

}

// Is called for every instruction and instruments syscalls
VOID Instruction(INS ins, VOID *v)
{
	// For O/S's (Mac) that don't support PIN_AddSyscallEntryFunction(),
	// instrument the system call instruction.

/*	if (INS_IsSyscall(ins) && INS_HasFallThrough(ins))
	{
		// Arguments and syscall number is only available before
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SysBefore),
			IARG_INST_PTR, IARG_SYSCALL_NUMBER,
			IARG_SYSARG_VALUE, 0, IARG_SYSARG_VALUE, 1,
			IARG_SYSARG_VALUE, 2, IARG_SYSARG_VALUE, 3,
			IARG_SYSARG_VALUE, 4, IARG_SYSARG_VALUE, 5,
			IARG_END);

		// return value only available after
		INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(SysAfter),
			IARG_SYSRET_VALUE,
			IARG_END);
	}
*/
	
	if (INS_IsSyscall(ins) /*&& INS_HasFallThrough(ins)*/)
	{
		// Arguments and syscall number is only available before
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(UpdateVector),IARG_FAST_ANALYSIS_CALL,
			IARG_THREAD_ID, IARG_SYSCALL_NUMBER,
			IARG_END);

		//fprintf(arrays, "HIT\n");
	}
	
}



VOID Fini(INT32 code, VOID *v)
{

	unsigned long test_count = 0;

	fseek(trace,0,SEEK_SET);
	fseek(trace2,0,SEEK_SET);
	fseek(threads,0,SEEK_SET);
	fseek(children,0,SEEK_SET);
	fseek(images,0,SEEK_SET);
	fseek(arrays,0,SEEK_SET);
	fseek(summary,0,SEEK_SET);
	fseek(array_dump,0,SEEK_SET);
	fseek(psh_out,0,SEEK_SET);
	fseek(context_out,0,SEEK_SET);


	fprintf(summary,"TOTAL_CALLS: %llu\nTOTAL_THREADS: %llu\n",total_calls,total_threads);
	fprintf(summary, "TOTAL_WIN32K_CALLS: %llu\n", total_win32k_calls);
	fprintf(summary, "TOTAL_NTDLL_CALLS: %llu\n", total_ntdll_calls);

	fprintf(stdout,"TOTAL_CALLS: %llu\nTOTAL_THREADS: %llu\n",total_calls,total_threads);
	fprintf(stdout, "TOTAL_WIN32K_CALLS: %llu\n", total_win32k_calls);
	fprintf(stdout, "TOTAL_NTDLL_CALLS: %llu\n", total_ntdll_calls);

	fwrite(&total_threads,sizeof(unsigned long long),1,array_dump);

	fprintf(summary, "TOTAL_THREADS_READ: %llu\n", total_threads);
	fprintf(stdout, "TOTAL_THREADS_READ: %llu\n", total_threads);

	for (unsigned long int i = 0; i < total_threads; i++)
	{
		test_count +=sam[i]->count;
//		fwrite(*(sam + i), sizeof(syscall_adj_matrix), 1, array_dump);
		fwrite(sam[i], sizeof(syscall_adj_matrix), 1, array_dump);
	}

//	fwrite(syscall_history,sizeof(unsigned short),total_ntdll_calls, trace2);
	

	fprintf(summary,"TEST_COUNT: %lu\n",test_count);
	fprintf(summary,"SIZE_OF_STRUCT: %lu\n",sizeof(syscall_adj_matrix));
	fprintf(summary,"SIZE_OF_LONG_LONG: %lu\n",sizeof(unsigned long long));
	fprintf(stdout,"TEST_COUNT: %lu\n",test_count);
	fprintf(stdout,"SIZE_OF_STRUCT: %lu\n",sizeof(syscall_adj_matrix));
	fprintf(stdout,"SIZE_OF_LONG_LONG: %lu\n",sizeof(unsigned long long));
#ifdef _DEBUG_STRACE
	fprintf(trace, "#eof\n");
#endif

#ifdef _DEBUG
	fprintf(children, "#eof\n");
	fprintf(images, "#eof\n");
	fprintf(arrays,"#eof\n");
	fprintf(summary, "#eof\n");
	//fprintf(array_dump, "#eof\n");
#endif

	fwrite(psh.array,sizeof(unsigned short),psh.count,psh_out);
	fwrite(context.array, sizeof(unsigned short), context.count, context_out);

	for (unsigned int i = 0; i < total_threads; i++)
	{
		fseek((*(tsh + i))->out,0,SEEK_SET);
		fwrite((*(tsh + i))->array, sizeof(unsigned short), (*(tsh + i))->count, (*(tsh + i))->out);
		fprintf(threads,"%s\n",clean_hash_string(thread_names + i*PR_MAX));
//		fclose((*(tsh + i))->out);
	}

//	fprintf(threads, "#eof\n");

/*	fclose(trace);
	fclose(trace2);
	fclose(threads);
	fclose(children);
	fclose(images);
	fclose(arrays);
	fclose(summary);
	fclose(array_dump);
	fclose(psh_out);
	fclose(context_out);
*/
	sync();
	std::cout << "PINTOOL Finished " << main_exe << " " << main_exe_iter << " " << getpid() << " last syscall was " << psh.array[psh.count-1] << std::endl;
}

VOID Start(VOID *v)
{
	char pid[1024];

	sprintf(pid,"%d\n",getpid());
	if(write(ver_fd,pid,strlen(pid) + 1) == -1)
	{
		printf("Error writing pid to file: %d, fd=%d\n",errno,ver_fd);
		error(1,errno,"%d\n",errno);
		exit(1);
	}
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
	PIN_ERROR("This tool prints a log of system calls"
		+ KNOB_BASE::StringKnobSummary() + "\n");
	return -1;
}

BOOL FollowChild(CHILD_PROCESS childProcess, VOID * userData)
{
#ifdef _DEBUG
//	fprintf(stdout, "before child:%u\n", _getpid());
//	fprintf(children, "before child:%u\n", _getpid());
#endif
	int pArgc;
	CHAR **pArgv;
	std::cout << "where program init needs to move\n";
	fprintf(debug,"where program init needs to move\n");
	CHILD_PROCESS_GetCommandLine(childProcess,&pArgc,(const CHAR *const**)&pArgv);
	for(int i=0;i<pArgc;i++)
		printf("%s ",pArgv[i]);
	printf("\n");
	return TRUE;
}

VOID ImageCallback(IMG image, VOID* userData)
{
	string img_name = IMG_Name(image);

#ifdef _DEBUG
	std::cout << "IMG NAME: " << img_name << endl;
	fprintf(images,"%s\n",img_name.c_str());
	fprintf(stdout, "%s\n", img_name.c_str());
#endif
}

VOID ThreadCallback(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
#ifdef _DEBUG
	std::cout << "Thead " << threadIndex << " started" << endl;
	fprintf(threads,"%u\n",threadIndex);
	fprintf(stdout, "%u\n", threadIndex);
#endif
	total_threads++;
	
	//fprintf(arrays, "ALLOCATE_ENTER\n");
	//fflush(arrays);
	(*(sam + threadIndex)) = (syscall_adj_matrix*)malloc(sizeof(syscall_adj_matrix));
	memset(*(sam + threadIndex), 0, sizeof(syscall_adj_matrix));
	//(*(sam + threadIndex))->array = (unsigned int*)malloc(sizeof(unsigned int)*402*401);
	(*(sam + threadIndex))->prev_sys = NULL_SYS;
	//allocate an array
	//fprintf(arrays, "ALLOCATE_EXIT\n");
	//fflush(arrays);
	char filename[1024];
	unsigned long long addr = PIN_GetContextReg(ctxt, REG_IP);
	sprintf(filename, "%sthread_%i_origin_%llx_%s_%d.out", logPath,threadIndex, addr,main_exe,main_exe_iter); 
	(*(tsh + threadIndex)) = (syscall_hist*)malloc(sizeof(syscall_hist));
	(*(tsh + threadIndex))->out = fopen(filename,"wb");
	init_hist(*(tsh + threadIndex));
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char *argv[])
{
	//MDP delete7
//	wchar_t pathname[1024];
//	char pathname2[1024];
//	wchar_t dest[1024];

	char *tmp_logpath;
	
	KNOB<string> KnobOutputPath(KNOB_MODE_WRITEONCE, "pintool",
		"p", ".\\", "specify output file name");


	main_exe = find_executable(argc,argv);

	if(main_exe == NULL)
	{
		printf("Error with finding exe basename\n");
		exit(1);
	}

	std::cout << "main exe is " << main_exe << endl;
	
	if (PIN_Init(argc, argv)) return Usage();

	if (strcmp(KnobOutputPath.Value().c_str(), ".\\") == 0)
		tmp_logpath = getcwd(logPath,1024);
		//WINDOWS::GetCurrentDirectory(1024, (WINDOWS::LPSTR)logPath);
	else
	{
		strcpy(logPath, KnobOutputPath.Value().c_str());
//		if (logPath[strlen(logPath) - 1] != '\\')
//			strcat(logPath,"\\");
	}

	tmp_logpath = tmp_logpath;

	if (logPath[strlen(logPath) - 1] != '/')
		strcat(logPath, "/");


	std::cout << "Option is " << logPath << endl;
	main_exe_iter = get_main_iter(logPath, main_exe,&ver_fd);
	std::cout << "iteration is " << main_exe_iter << " fd= " << ver_fd << endl;

	/*
	InitializeSecurityDescriptor(&sd,0);
	
	SetSecurityDescriptorDacl(&sd,true,NULL,false);
	SetSecurityDescriptorOwner(&sd,NULL,false);
	SetSecurityDescriptorGroup(&sd,NULL,false);
	
	sa.lpSecurityDescriptor = &sd;
	sa.nLength = sizeof(SECURITY_DESCRIPTOR);


	*/



	sam = (syscall_adj_matrix**) malloc(sizeof(syscall_adj_matrix*) * NUM_THREADS);

	thread_names = (char*)malloc(PR_MAX * NUM_THREADS);
	memset(thread_names,0,PR_MAX * NUM_THREADS);

	init_hist(&psh);
	init_hist(&context);
	tsh = (syscall_hist**) malloc(sizeof(syscall_hist*) * NUM_THREADS);
	//Make a debugging praga.  SLOW
	                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         
	
	//WINDOWS::SetCurrentDirectory(logPath);
	//std::cout << "result is " << _chdir(logPath) << endl;

	char fullPath[1024];
//	trace = fopen("strace.out", "wb");
	sprintf(fullPath,"%sstrace_%s_%d.out",logPath,main_exe,main_exe_iter);
	trace = fopen(fullPath, "wb");

	sprintf(fullPath, "%sstrace2_%s_%d.out", logPath, main_exe,main_exe_iter);
	trace2 = fopen(fullPath, "wb");

	sprintf(fullPath, "%sthreads_%s_%d.out", logPath, main_exe,main_exe_iter);
	threads = fopen(fullPath, "wb");

	sprintf(fullPath, "%simages_%s_%d.out", logPath, main_exe,main_exe_iter);
	images = fopen(fullPath, "wb");

	sprintf(fullPath, "%schildren_%s_%d.out", logPath, main_exe,main_exe_iter);
	children = fopen(fullPath, "wb");

	sprintf(fullPath, "%sdebug_%s_%d.out", logPath, main_exe,main_exe_iter);
	debug = fopen(fullPath, "wb");

	sprintf(fullPath, "%scall-stack_%s_%d.out", logPath, main_exe,main_exe_iter);
	call_stack = fopen(fullPath, "wb");

	sprintf(fullPath, "%sarrays_%s_%d.out", logPath, main_exe,main_exe_iter);
	arrays = fopen(fullPath, "wb");

	sprintf(fullPath, "%ssummary_%s_%d.out", logPath, main_exe,main_exe_iter);
	summary = fopen(fullPath, "wb");

	sprintf(fullPath, "%sarray_dump_%s_%d.out", logPath, main_exe,main_exe_iter);
	array_dump = fopen(fullPath	, "wb");

	sprintf(fullPath, "%spsh_%s_%d.out", logPath, main_exe,main_exe_iter);
	psh_out = fopen(fullPath,"wb");

	sprintf(fullPath, "%scontext_%s_%d.out", logPath, main_exe,main_exe_iter);
	context_out = fopen(fullPath, "wb");

	printf("start %d\n",getpid());
	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddSyscallEntryFunction(SyscallEntry, 0);
	PIN_AddSyscallExitFunction(SyscallExit, 0);

	PIN_AddApplicationStartFunction(Start,0);	
	PIN_AddFiniFunction(Fini, 0);

	//For following child processes
	PIN_AddFollowChildProcessFunction(FollowChild, 0);
#ifdef _DEBUG
	IMG_AddInstrumentFunction(ImageCallback,0);
#endif
	PIN_AddThreadStartFunction(ThreadCallback,0);
	
	PIN_InitLock(&lock);
	PIN_InitLock(&lock_deleteme);
	PIN_InitLock(&lock_sh);

#ifdef _DEBUG_CALLSTACK
	//Very SLOW!!!!!!
	CALLSTACK::CallStackManager::get_instance()->activate();
	csm->activate();
#endif
	// Never returns
	PIN_StartProgram();

	return 0;
}


void syscall_ntos(long num, char* dest)
{
	switch (num)
	{
	case SP0_NTACCEPTCONNECTPORT:
		strcpy(dest, sNTACCEPTCONNECTPORT);
		break;
	case SP0_NTACCESSCHECK:
		strcpy(dest, sNTACCESSCHECK);
		break;
	case SP0_NTACCESSCHECKANDAUDITALARM:
		strcpy(dest, sNTACCESSCHECKANDAUDITALARM);
		break;
	case SP0_NTACCESSCHECKBYTYPE:
		strcpy(dest, sNTACCESSCHECKBYTYPE);
		break;
	case SP0_NTACCESSCHECKBYTYPEANDAUDITALARM:
		strcpy(dest, sNTACCESSCHECKBYTYPEANDAUDITALARM);
		break;
	case SP0_NTACCESSCHECKBYTYPERESULTLIST:
		strcpy(dest, sNTACCESSCHECKBYTYPERESULTLIST);
		break;
	case SP0_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARM:
		strcpy(dest, sNTACCESSCHECKBYTYPERESULTLISTANDAUDITALARM);
		break;
	case SP0_NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE:
		strcpy(dest, sNTACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE);
		break;
	case SP0_NTADDATOM:
		strcpy(dest, sNTADDATOM);
		break;
	case SP0_NTADDBOOTENTRY:
		strcpy(dest, sNTADDBOOTENTRY);
		break;
	case SP0_NTADDDRIVERENTRY:
		strcpy(dest, sNTADDDRIVERENTRY);
		break;
	case SP0_NTADJUSTGROUPSTOKEN:
		strcpy(dest, sNTADJUSTGROUPSTOKEN);
		break;
	case SP0_NTADJUSTPRIVILEGESTOKEN:
		strcpy(dest, sNTADJUSTPRIVILEGESTOKEN);
		break;
	case SP0_NTALERTRESUMETHREAD:
		strcpy(dest, sNTALERTRESUMETHREAD);
		break;
	case SP0_NTALERTTHREAD:
		strcpy(dest, sNTALERTTHREAD);
		break;
	case SP0_NTALLOCATELOCALLYUNIQUEID:
		strcpy(dest, sNTALLOCATELOCALLYUNIQUEID);
		break;
	case SP0_NTALLOCATERESERVEOBJECT:
		strcpy(dest, sNTALLOCATERESERVEOBJECT);
		break;
	case SP0_NTALLOCATEUSERPHYSICALPAGES:
		strcpy(dest, sNTALLOCATEUSERPHYSICALPAGES);
		break;
	case SP0_NTALLOCATEUUIDS:
		strcpy(dest, sNTALLOCATEUUIDS);
		break;
	case SP0_NTALLOCATEVIRTUALMEMORY:
		strcpy(dest, sNTALLOCATEVIRTUALMEMORY);
		break;
	case SP0_NTALPCACCEPTCONNECTPORT:
		strcpy(dest, sNTALPCACCEPTCONNECTPORT);
		break;
	case SP0_NTALPCCANCELMESSAGE:
		strcpy(dest, sNTALPCCANCELMESSAGE);
		break;
	case SP0_NTALPCCONNECTPORT:
		strcpy(dest, sNTALPCCONNECTPORT);
		break;
	case SP0_NTALPCCREATEPORT:
		strcpy(dest, sNTALPCCREATEPORT);
		break;
	case SP0_NTALPCCREATEPORTSECTION:
		strcpy(dest, sNTALPCCREATEPORTSECTION);
		break;
	case SP0_NTALPCCREATERESOURCERESERVE:
		strcpy(dest, sNTALPCCREATERESOURCERESERVE);
		break;
	case SP0_NTALPCCREATESECTIONVIEW:
		strcpy(dest, sNTALPCCREATESECTIONVIEW);
		break;
	case SP0_NTALPCCREATESECURITYCONTEXT:
		strcpy(dest, sNTALPCCREATESECURITYCONTEXT);
		break;
	case SP0_NTALPCDELETEPORTSECTION:
		strcpy(dest, sNTALPCDELETEPORTSECTION);
		break;
	case SP0_NTALPCDELETERESOURCERESERVE:
		strcpy(dest, sNTALPCDELETERESOURCERESERVE);
		break;
	case SP0_NTALPCDELETESECTIONVIEW:
		strcpy(dest, sNTALPCDELETESECTIONVIEW);
		break;
	case SP0_NTALPCDELETESECURITYCONTEXT:
		strcpy(dest, sNTALPCDELETESECURITYCONTEXT);
		break;
	case SP0_NTALPCDISCONNECTPORT:
		strcpy(dest, sNTALPCDISCONNECTPORT);
		break;
	case SP0_NTALPCIMPERSONATECLIENTOFPORT:
		strcpy(dest, sNTALPCIMPERSONATECLIENTOFPORT);
		break;
	case SP0_NTALPCOPENSENDERPROCESS:
		strcpy(dest, sNTALPCOPENSENDERPROCESS);
		break;
	case SP0_NTALPCOPENSENDERTHREAD:
		strcpy(dest, sNTALPCOPENSENDERTHREAD);
		break;
	case SP0_NTALPCQUERYINFORMATION:
		strcpy(dest, sNTALPCQUERYINFORMATION);
		break;
	case SP0_NTALPCQUERYINFORMATIONMESSAGE:
		strcpy(dest, sNTALPCQUERYINFORMATIONMESSAGE);
		break;
	case SP0_NTALPCREVOKESECURITYCONTEXT:
		strcpy(dest, sNTALPCREVOKESECURITYCONTEXT);
		break;
	case SP0_NTALPCSENDWAITRECEIVEPORT:
		strcpy(dest, sNTALPCSENDWAITRECEIVEPORT);
		break;
	case SP0_NTALPCSETINFORMATION:
		strcpy(dest, sNTALPCSETINFORMATION);
		break;
	case SP0_NTAPPHELPCACHECONTROL:
		strcpy(dest, sNTAPPHELPCACHECONTROL);
		break;
	case SP0_NTAREMAPPEDFILESTHESAME:
		strcpy(dest, sNTAREMAPPEDFILESTHESAME);
		break;
	case SP0_NTASSIGNPROCESSTOJOBOBJECT:
		strcpy(dest, sNTASSIGNPROCESSTOJOBOBJECT);
		break;
	case SP0_NTCALLBACKRETURN:
		strcpy(dest, sNTCALLBACKRETURN);
		break;
	case SP0_NTCANCELIOFILE:
		strcpy(dest, sNTCANCELIOFILE);
		break;
	case SP0_NTCANCELIOFILEEX:
		strcpy(dest, sNTCANCELIOFILEEX);
		break;
	case SP0_NTCANCELSYNCHRONOUSIOFILE:
		strcpy(dest, sNTCANCELSYNCHRONOUSIOFILE);
		break;
	case SP0_NTCANCELTIMER:
		strcpy(dest, sNTCANCELTIMER);
		break;
	case SP0_NTCLEAREVENT:
		strcpy(dest, sNTCLEAREVENT);
		break;
	case SP0_NTCLOSE:
		strcpy(dest, sNTCLOSE);
		break;
	case SP0_NTCLOSEOBJECTAUDITALARM:
		strcpy(dest, sNTCLOSEOBJECTAUDITALARM);
		break;
	case SP0_NTCOMMITCOMPLETE:
		strcpy(dest, sNTCOMMITCOMPLETE);
		break;
	case SP0_NTCOMMITENLISTMENT:
		strcpy(dest, sNTCOMMITENLISTMENT);
		break;
	case SP0_NTCOMMITTRANSACTION:
		strcpy(dest, sNTCOMMITTRANSACTION);
		break;
	case SP0_NTCOMPACTKEYS:
		strcpy(dest, sNTCOMPACTKEYS);
		break;
	case SP0_NTCOMPARETOKENS:
		strcpy(dest, sNTCOMPARETOKENS);
		break;
	case SP0_NTCOMPRESSKEY:
		strcpy(dest, sNTCOMPRESSKEY);
		break;
	case SP0_NTCONNECTPORT:
		strcpy(dest, sNTCONNECTPORT);
		break;
	case SP0_NTCONTINUE:
		strcpy(dest, sNTCONTINUE);
		break;
	case SP0_NTCREATEDEBUGOBJECT:
		strcpy(dest, sNTCREATEDEBUGOBJECT);
		break;
	case SP0_NTCREATEDIRECTORYOBJECT:
		strcpy(dest, sNTCREATEDIRECTORYOBJECT);
		break;
	case SP0_NTCREATEENLISTMENT:
		strcpy(dest, sNTCREATEENLISTMENT);
		break;
	case SP0_NTCREATEEVENT:
		strcpy(dest, sNTCREATEEVENT);
		break;
	case SP0_NTCREATEEVENTPAIR:
		strcpy(dest, sNTCREATEEVENTPAIR);
		break;
	case SP0_NTCREATEFILE:
		strcpy(dest, sNTCREATEFILE);
		break;
	case SP0_NTCREATEIOCOMPLETION:
		strcpy(dest, sNTCREATEIOCOMPLETION);
		break;
	case SP0_NTCREATEJOBOBJECT:
		strcpy(dest, sNTCREATEJOBOBJECT);
		break;
	case SP0_NTCREATEJOBSET:
		strcpy(dest, sNTCREATEJOBSET);
		break;
	case SP0_NTCREATEKEY:
		strcpy(dest, sNTCREATEKEY);
		break;
	case SP0_NTCREATEKEYTRANSACTED:
		strcpy(dest, sNTCREATEKEYTRANSACTED);
		break;
	case SP0_NTCREATEKEYEDEVENT:
		strcpy(dest, sNTCREATEKEYEDEVENT);
		break;
	case SP0_NTCREATEMAILSLOTFILE:
		strcpy(dest, sNTCREATEMAILSLOTFILE);
		break;
	case SP0_NTCREATEMUTANT:
		strcpy(dest, sNTCREATEMUTANT);
		break;
	case SP0_NTCREATENAMEDPIPEFILE:
		strcpy(dest, sNTCREATENAMEDPIPEFILE);
		break;
	case SP0_NTCREATEPAGINGFILE:
		strcpy(dest, sNTCREATEPAGINGFILE);
		break;
	case SP0_NTCREATEPORT:
		strcpy(dest, sNTCREATEPORT);
		break;
	case SP0_NTCREATEPRIVATENAMESPACE:
		strcpy(dest, sNTCREATEPRIVATENAMESPACE);
		break;
	case SP0_NTCREATEPROCESS:
		strcpy(dest, sNTCREATEPROCESS);
		break;
	case SP0_NTCREATEPROCESSEX:
		strcpy(dest, sNTCREATEPROCESSEX);
		break;
	case SP0_NTCREATEPROFILE:
		strcpy(dest, sNTCREATEPROFILE);
		break;
	case SP0_NTCREATEPROFILEEX:
		strcpy(dest, sNTCREATEPROFILEEX);
		break;
	case SP0_NTCREATERESOURCEMANAGER:
		strcpy(dest, sNTCREATERESOURCEMANAGER);
		break;
	case SP0_NTCREATESECTION:
		strcpy(dest, sNTCREATESECTION);
		break;
	case SP0_NTCREATESEMAPHORE:
		strcpy(dest, sNTCREATESEMAPHORE);
		break;
	case SP0_NTCREATESYMBOLICLINKOBJECT:
		strcpy(dest, sNTCREATESYMBOLICLINKOBJECT);
		break;
	case SP0_NTCREATETHREAD:
		strcpy(dest, sNTCREATETHREAD);
		break;
	case SP0_NTCREATETHREADEX:
		strcpy(dest, sNTCREATETHREADEX);
		break;
	case SP0_NTCREATETIMER:
		strcpy(dest, sNTCREATETIMER);
		break;
	case SP0_NTCREATETOKEN:
		strcpy(dest, sNTCREATETOKEN);
		break;
	case SP0_NTCREATETRANSACTION:
		strcpy(dest, sNTCREATETRANSACTION);
		break;
	case SP0_NTCREATETRANSACTIONMANAGER:
		strcpy(dest, sNTCREATETRANSACTIONMANAGER);
		break;
	case SP0_NTCREATEUSERPROCESS:
		strcpy(dest, sNTCREATEUSERPROCESS);
		break;
	case SP0_NTCREATEWAITABLEPORT:
		strcpy(dest, sNTCREATEWAITABLEPORT);
		break;
	case SP0_NTCREATEWORKERFACTORY:
		strcpy(dest, sNTCREATEWORKERFACTORY);
		break;
	case SP0_NTDEBUGACTIVEPROCESS:
		strcpy(dest, sNTDEBUGACTIVEPROCESS);
		break;
	case SP0_NTDEBUGCONTINUE:
		strcpy(dest, sNTDEBUGCONTINUE);
		break;
	case SP0_NTDELAYEXECUTION:
		strcpy(dest, sNTDELAYEXECUTION);
		break;
	case SP0_NTDELETEATOM:
		strcpy(dest, sNTDELETEATOM);
		break;
	case SP0_NTDELETEBOOTENTRY:
		strcpy(dest, sNTDELETEBOOTENTRY);
		break;
	case SP0_NTDELETEDRIVERENTRY:
		strcpy(dest, sNTDELETEDRIVERENTRY);
		break;
	case SP0_NTDELETEFILE:
		strcpy(dest, sNTDELETEFILE);
		break;
	case SP0_NTDELETEKEY:
		strcpy(dest, sNTDELETEKEY);
		break;
	case SP0_NTDELETEOBJECTAUDITALARM:
		strcpy(dest, sNTDELETEOBJECTAUDITALARM);
		break;
	case SP0_NTDELETEPRIVATENAMESPACE:
		strcpy(dest, sNTDELETEPRIVATENAMESPACE);
		break;
	case SP0_NTDELETEVALUEKEY:
		strcpy(dest, sNTDELETEVALUEKEY);
		break;
	case SP0_NTDEVICEIOCONTROLFILE:
		strcpy(dest, sNTDEVICEIOCONTROLFILE);
		break;
	case SP0_NTDISABLELASTKNOWNGOOD:
		strcpy(dest, sNTDISABLELASTKNOWNGOOD);
		break;
	case SP0_NTDISPLAYSTRING:
		strcpy(dest, sNTDISPLAYSTRING);
		break;
	case SP0_NTDRAWTEXT:
		strcpy(dest, sNTDRAWTEXT);
		break;
	case SP0_NTDUPLICATEOBJECT:
		strcpy(dest, sNTDUPLICATEOBJECT);
		break;
	case SP0_NTDUPLICATETOKEN:
		strcpy(dest, sNTDUPLICATETOKEN);
		break;
	case SP0_NTENABLELASTKNOWNGOOD:
		strcpy(dest, sNTENABLELASTKNOWNGOOD);
		break;
	case SP0_NTENUMERATEBOOTENTRIES:
		strcpy(dest, sNTENUMERATEBOOTENTRIES);
		break;
	case SP0_NTENUMERATEDRIVERENTRIES:
		strcpy(dest, sNTENUMERATEDRIVERENTRIES);
		break;
	case SP0_NTENUMERATEKEY:
		strcpy(dest, sNTENUMERATEKEY);
		break;
	case SP0_NTENUMERATESYSTEMENVIRONMENTVALUESEX:
		strcpy(dest, sNTENUMERATESYSTEMENVIRONMENTVALUESEX);
		break;
	case SP0_NTENUMERATETRANSACTIONOBJECT:
		strcpy(dest, sNTENUMERATETRANSACTIONOBJECT);
		break;
	case SP0_NTENUMERATEVALUEKEY:
		strcpy(dest, sNTENUMERATEVALUEKEY);
		break;
	case SP0_NTEXTENDSECTION:
		strcpy(dest, sNTEXTENDSECTION);
		break;
	case SP0_NTFILTERTOKEN:
		strcpy(dest, sNTFILTERTOKEN);
		break;
	case SP0_NTFINDATOM:
		strcpy(dest, sNTFINDATOM);
		break;
	case SP0_NTFLUSHBUFFERSFILE:
		strcpy(dest, sNTFLUSHBUFFERSFILE);
		break;
	case SP0_NTFLUSHINSTALLUILANGUAGE:
		strcpy(dest, sNTFLUSHINSTALLUILANGUAGE);
		break;
	case SP0_NTFLUSHINSTRUCTIONCACHE:
		strcpy(dest, sNTFLUSHINSTRUCTIONCACHE);
		break;
	case SP0_NTFLUSHKEY:
		strcpy(dest, sNTFLUSHKEY);
		break;
	case SP0_NTFLUSHPROCESSWRITEBUFFERS:
		strcpy(dest, sNTFLUSHPROCESSWRITEBUFFERS);
		break;
	case SP0_NTFLUSHVIRTUALMEMORY:
		strcpy(dest, sNTFLUSHVIRTUALMEMORY);
		break;
	case SP0_NTFLUSHWRITEBUFFER:
		strcpy(dest, sNTFLUSHWRITEBUFFER);
		break;
	case SP0_NTFREEUSERPHYSICALPAGES:
		strcpy(dest, sNTFREEUSERPHYSICALPAGES);
		break;
	case SP0_NTFREEVIRTUALMEMORY:
		strcpy(dest, sNTFREEVIRTUALMEMORY);
		break;
	case SP0_NTFREEZEREGISTRY:
		strcpy(dest, sNTFREEZEREGISTRY);
		break;
	case SP0_NTFREEZETRANSACTIONS:
		strcpy(dest, sNTFREEZETRANSACTIONS);
		break;
	case SP0_NTFSCONTROLFILE:
		strcpy(dest, sNTFSCONTROLFILE);
		break;
	case SP0_NTGETCONTEXTTHREAD:
		strcpy(dest, sNTGETCONTEXTTHREAD);
		break;
	case SP0_NTGETCURRENTPROCESSORNUMBER:
		strcpy(dest, sNTGETCURRENTPROCESSORNUMBER);
		break;
	case SP0_NTGETDEVICEPOWERSTATE:
		strcpy(dest, sNTGETDEVICEPOWERSTATE);
		break;
	case SP0_NTGETMUIREGISTRYINFO:
		strcpy(dest, sNTGETMUIREGISTRYINFO);
		break;
	case SP0_NTGETNEXTPROCESS:
		strcpy(dest, sNTGETNEXTPROCESS);
		break;
	case SP0_NTGETNEXTTHREAD:
		strcpy(dest, sNTGETNEXTTHREAD);
		break;
	case SP0_NTGETNLSSECTIONPTR:
		strcpy(dest, sNTGETNLSSECTIONPTR);
		break;
	case SP0_NTGETNOTIFICATIONRESOURCEMANAGER:
		strcpy(dest, sNTGETNOTIFICATIONRESOURCEMANAGER);
		break;
	case SP0_NTGETPLUGPLAYEVENT:
		strcpy(dest, sNTGETPLUGPLAYEVENT);
		break;
	case SP0_NTGETWRITEWATCH:
		strcpy(dest, sNTGETWRITEWATCH);
		break;
	case SP0_NTIMPERSONATEANONYMOUSTOKEN:
		strcpy(dest, sNTIMPERSONATEANONYMOUSTOKEN);
		break;
	case SP0_NTIMPERSONATECLIENTOFPORT:
		strcpy(dest, sNTIMPERSONATECLIENTOFPORT);
		break;
	case SP0_NTIMPERSONATETHREAD:
		strcpy(dest, sNTIMPERSONATETHREAD);
		break;
	case SP0_NTINITIALIZENLSFILES:
		strcpy(dest, sNTINITIALIZENLSFILES);
		break;
	case SP0_NTINITIALIZEREGISTRY:
		strcpy(dest, sNTINITIALIZEREGISTRY);
		break;
	case SP0_NTINITIATEPOWERACTION:
		strcpy(dest, sNTINITIATEPOWERACTION);
		break;
	case SP0_NTISPROCESSINJOB:
		strcpy(dest, sNTISPROCESSINJOB);
		break;
	case SP0_NTISSYSTEMRESUMEAUTOMATIC:
		strcpy(dest, sNTISSYSTEMRESUMEAUTOMATIC);
		break;
	case SP0_NTISUILANGUAGECOMITTED:
		strcpy(dest, sNTISUILANGUAGECOMITTED);
		break;
	case SP0_NTLISTENPORT:
		strcpy(dest, sNTLISTENPORT);
		break;
	case SP0_NTLOADDRIVER:
		strcpy(dest, sNTLOADDRIVER);
		break;
	case SP0_NTLOADKEY:
		strcpy(dest, sNTLOADKEY);
		break;
	case SP0_NTLOADKEY2:
		strcpy(dest, sNTLOADKEY2);
		break;
	case SP0_NTLOADKEYEX:
		strcpy(dest, sNTLOADKEYEX);
		break;
	case SP0_NTLOCKFILE:
		strcpy(dest, sNTLOCKFILE);
		break;
	case SP0_NTLOCKPRODUCTACTIVATIONKEYS:
		strcpy(dest, sNTLOCKPRODUCTACTIVATIONKEYS);
		break;
	case SP0_NTLOCKREGISTRYKEY:
		strcpy(dest, sNTLOCKREGISTRYKEY);
		break;
	case SP0_NTLOCKVIRTUALMEMORY:
		strcpy(dest, sNTLOCKVIRTUALMEMORY);
		break;
	case SP0_NTMAKEPERMANENTOBJECT:
		strcpy(dest, sNTMAKEPERMANENTOBJECT);
		break;
	case SP0_NTMAKETEMPORARYOBJECT:
		strcpy(dest, sNTMAKETEMPORARYOBJECT);
		break;
	case SP0_NTMAPCMFMODULE:
		strcpy(dest, sNTMAPCMFMODULE);
		break;
	case SP0_NTMAPUSERPHYSICALPAGES:
		strcpy(dest, sNTMAPUSERPHYSICALPAGES);
		break;
	case SP0_NTMAPUSERPHYSICALPAGESSCATTER:
		strcpy(dest, sNTMAPUSERPHYSICALPAGESSCATTER);
		break;
	case SP0_NTMAPVIEWOFSECTION:
		strcpy(dest, sNTMAPVIEWOFSECTION);
		break;
	case SP0_NTMODIFYBOOTENTRY:
		strcpy(dest, sNTMODIFYBOOTENTRY);
		break;
	case SP0_NTMODIFYDRIVERENTRY:
		strcpy(dest, sNTMODIFYDRIVERENTRY);
		break;
	case SP0_NTNOTIFYCHANGEDIRECTORYFILE:
		strcpy(dest, sNTNOTIFYCHANGEDIRECTORYFILE);
		break;
	case SP0_NTNOTIFYCHANGEKEY:
		strcpy(dest, sNTNOTIFYCHANGEKEY);
		break;
	case SP0_NTNOTIFYCHANGEMULTIPLEKEYS:
		strcpy(dest, sNTNOTIFYCHANGEMULTIPLEKEYS);
		break;
	case SP0_NTNOTIFYCHANGESESSION:
		strcpy(dest, sNTNOTIFYCHANGESESSION);
		break;
	case SP0_NTOPENDIRECTORYOBJECT:
		strcpy(dest, sNTOPENDIRECTORYOBJECT);
		break;
	case SP0_NTOPENENLISTMENT:
		strcpy(dest, sNTOPENENLISTMENT);
		break;
	case SP0_NTOPENEVENT:
		strcpy(dest, sNTOPENEVENT);
		break;
	case SP0_NTOPENEVENTPAIR:
		strcpy(dest, sNTOPENEVENTPAIR);
		break;
	case SP0_NTOPENFILE:
		strcpy(dest, sNTOPENFILE);
		break;
	case SP0_NTOPENIOCOMPLETION:
		strcpy(dest, sNTOPENIOCOMPLETION);
		break;
	case SP0_NTOPENJOBOBJECT:
		strcpy(dest, sNTOPENJOBOBJECT);
		break;
	case SP0_NTOPENKEY:
		strcpy(dest, sNTOPENKEY);
		break;
	case SP0_NTOPENKEYEX:
		strcpy(dest, sNTOPENKEYEX);
		break;
	case SP0_NTOPENKEYTRANSACTED:
		strcpy(dest, sNTOPENKEYTRANSACTED);
		break;
	case SP0_NTOPENKEYTRANSACTEDEX:
		strcpy(dest, sNTOPENKEYTRANSACTEDEX);
		break;
	case SP0_NTOPENKEYEDEVENT:
		strcpy(dest, sNTOPENKEYEDEVENT);
		break;
	case SP0_NTOPENMUTANT:
		strcpy(dest, sNTOPENMUTANT);
		break;
	case SP0_NTOPENOBJECTAUDITALARM:
		strcpy(dest, sNTOPENOBJECTAUDITALARM);
		break;
	case SP0_NTOPENPRIVATENAMESPACE:
		strcpy(dest, sNTOPENPRIVATENAMESPACE);
		break;
	case SP0_NTOPENPROCESS:
		strcpy(dest, sNTOPENPROCESS);
		break;
	case SP0_NTOPENPROCESSTOKEN:
		strcpy(dest, sNTOPENPROCESSTOKEN);
		break;
	case SP0_NTOPENPROCESSTOKENEX:
		strcpy(dest, sNTOPENPROCESSTOKENEX);
		break;
	case SP0_NTOPENRESOURCEMANAGER:
		strcpy(dest, sNTOPENRESOURCEMANAGER);
		break;
	case SP0_NTOPENSECTION:
		strcpy(dest, sNTOPENSECTION);
		break;
	case SP0_NTOPENSEMAPHORE:
		strcpy(dest, sNTOPENSEMAPHORE);
		break;
	case SP0_NTOPENSESSION:
		strcpy(dest, sNTOPENSESSION);
		break;
	case SP0_NTOPENSYMBOLICLINKOBJECT:
		strcpy(dest, sNTOPENSYMBOLICLINKOBJECT);
		break;
	case SP0_NTOPENTHREAD:
		strcpy(dest, sNTOPENTHREAD);
		break;
	case SP0_NTOPENTHREADTOKEN:
		strcpy(dest, sNTOPENTHREADTOKEN);
		break;
	case SP0_NTOPENTHREADTOKENEX:
		strcpy(dest, sNTOPENTHREADTOKENEX);
		break;
	case SP0_NTOPENTIMER:
		strcpy(dest, sNTOPENTIMER);
		break;
	case SP0_NTOPENTRANSACTION:
		strcpy(dest, sNTOPENTRANSACTION);
		break;
	case SP0_NTOPENTRANSACTIONMANAGER:
		strcpy(dest, sNTOPENTRANSACTIONMANAGER);
		break;
	case SP0_NTPLUGPLAYCONTROL:
		strcpy(dest, sNTPLUGPLAYCONTROL);
		break;
	case SP0_NTPOWERINFORMATION:
		strcpy(dest, sNTPOWERINFORMATION);
		break;
	case SP0_NTPREPREPARECOMPLETE:
		strcpy(dest, sNTPREPREPARECOMPLETE);
		break;
	case SP0_NTPREPREPAREENLISTMENT:
		strcpy(dest, sNTPREPREPAREENLISTMENT);
		break;
	case SP0_NTPREPARECOMPLETE:
		strcpy(dest, sNTPREPARECOMPLETE);
		break;
	case SP0_NTPREPAREENLISTMENT:
		strcpy(dest, sNTPREPAREENLISTMENT);
		break;
	case SP0_NTPRIVILEGECHECK:
		strcpy(dest, sNTPRIVILEGECHECK);
		break;
	case SP0_NTPRIVILEGEOBJECTAUDITALARM:
		strcpy(dest, sNTPRIVILEGEOBJECTAUDITALARM);
		break;
	case SP0_NTPRIVILEGEDSERVICEAUDITALARM:
		strcpy(dest, sNTPRIVILEGEDSERVICEAUDITALARM);
		break;
	case SP0_NTPROPAGATIONCOMPLETE:
		strcpy(dest, sNTPROPAGATIONCOMPLETE);
		break;
	case SP0_NTPROPAGATIONFAILED:
		strcpy(dest, sNTPROPAGATIONFAILED);
		break;
	case SP0_NTPROTECTVIRTUALMEMORY:
		strcpy(dest, sNTPROTECTVIRTUALMEMORY);
		break;
	case SP0_NTPULSEEVENT:
		strcpy(dest, sNTPULSEEVENT);
		break;
	case SP0_NTQUERYATTRIBUTESFILE:
		strcpy(dest, sNTQUERYATTRIBUTESFILE);
		break;
	case SP0_NTQUERYBOOTENTRYORDER:
		strcpy(dest, sNTQUERYBOOTENTRYORDER);
		break;
	case SP0_NTQUERYBOOTOPTIONS:
		strcpy(dest, sNTQUERYBOOTOPTIONS);
		break;
	case SP0_NTQUERYDEBUGFILTERSTATE:
		strcpy(dest, sNTQUERYDEBUGFILTERSTATE);
		break;
	case SP0_NTQUERYDEFAULTLOCALE:
		strcpy(dest, sNTQUERYDEFAULTLOCALE);
		break;
	case SP0_NTQUERYDEFAULTUILANGUAGE:
		strcpy(dest, sNTQUERYDEFAULTUILANGUAGE);
		break;
	case SP0_NTQUERYDIRECTORYFILE:
		strcpy(dest, sNTQUERYDIRECTORYFILE);
		break;
	case SP0_NTQUERYDIRECTORYOBJECT:
		strcpy(dest, sNTQUERYDIRECTORYOBJECT);
		break;
	case SP0_NTQUERYDRIVERENTRYORDER:
		strcpy(dest, sNTQUERYDRIVERENTRYORDER);
		break;
	case SP0_NTQUERYEAFILE:
		strcpy(dest, sNTQUERYEAFILE);
		break;
	case SP0_NTQUERYEVENT:
		strcpy(dest, sNTQUERYEVENT);
		break;
	case SP0_NTQUERYFULLATTRIBUTESFILE:
		strcpy(dest, sNTQUERYFULLATTRIBUTESFILE);
		break;
	case SP0_NTQUERYINFORMATIONATOM:
		strcpy(dest, sNTQUERYINFORMATIONATOM);
		break;
	case SP0_NTQUERYINFORMATIONENLISTMENT:
		strcpy(dest, sNTQUERYINFORMATIONENLISTMENT);
		break;
	case SP0_NTQUERYINFORMATIONFILE:
		strcpy(dest, sNTQUERYINFORMATIONFILE);
		break;
	case SP0_NTQUERYINFORMATIONJOBOBJECT:
		strcpy(dest, sNTQUERYINFORMATIONJOBOBJECT);
		break;
	case SP0_NTQUERYINFORMATIONPORT:
		strcpy(dest, sNTQUERYINFORMATIONPORT);
		break;
	case SP0_NTQUERYINFORMATIONPROCESS:
		strcpy(dest, sNTQUERYINFORMATIONPROCESS);
		break;
	case SP0_NTQUERYINFORMATIONRESOURCEMANAGER:
		strcpy(dest, sNTQUERYINFORMATIONRESOURCEMANAGER);
		break;
	case SP0_NTQUERYINFORMATIONTHREAD:
		strcpy(dest, sNTQUERYINFORMATIONTHREAD);
		break;
	case SP0_NTQUERYINFORMATIONTOKEN:
		strcpy(dest, sNTQUERYINFORMATIONTOKEN);
		break;
	case SP0_NTQUERYINFORMATIONTRANSACTION:
		strcpy(dest, sNTQUERYINFORMATIONTRANSACTION);
		break;
	case SP0_NTQUERYINFORMATIONTRANSACTIONMANAGER:
		strcpy(dest, sNTQUERYINFORMATIONTRANSACTIONMANAGER);
		break;
	case SP0_NTQUERYINFORMATIONWORKERFACTORY:
		strcpy(dest, sNTQUERYINFORMATIONWORKERFACTORY);
		break;
	case SP0_NTQUERYINSTALLUILANGUAGE:
		strcpy(dest, sNTQUERYINSTALLUILANGUAGE);
		break;
	case SP0_NTQUERYINTERVALPROFILE:
		strcpy(dest, sNTQUERYINTERVALPROFILE);
		break;
	case SP0_NTQUERYIOCOMPLETION:
		strcpy(dest, sNTQUERYIOCOMPLETION);
		break;
	case SP0_NTQUERYKEY:
		strcpy(dest, sNTQUERYKEY);
		break;
	case SP0_NTQUERYLICENSEVALUE:
		strcpy(dest, sNTQUERYLICENSEVALUE);
		break;
	case SP0_NTQUERYMULTIPLEVALUEKEY:
		strcpy(dest, sNTQUERYMULTIPLEVALUEKEY);
		break;
	case SP0_NTQUERYMUTANT:
		strcpy(dest, sNTQUERYMUTANT);
		break;
	case SP0_NTQUERYOBJECT:
		strcpy(dest, sNTQUERYOBJECT);
		break;
	case SP0_NTQUERYOPENSUBKEYS:
		strcpy(dest, sNTQUERYOPENSUBKEYS);
		break;
	case SP0_NTQUERYOPENSUBKEYSEX:
		strcpy(dest, sNTQUERYOPENSUBKEYSEX);
		break;
	case SP0_NTQUERYPERFORMANCECOUNTER:
		strcpy(dest, sNTQUERYPERFORMANCECOUNTER);
		break;
	case SP0_NTQUERYPORTINFORMATIONPROCESS:
		strcpy(dest, sNTQUERYPORTINFORMATIONPROCESS);
		break;
	case SP0_NTQUERYQUOTAINFORMATIONFILE:
		strcpy(dest, sNTQUERYQUOTAINFORMATIONFILE);
		break;
	case SP0_NTQUERYSECTION:
		strcpy(dest, sNTQUERYSECTION);
		break;
	case SP0_NTQUERYSECURITYATTRIBUTESTOKEN:
		strcpy(dest, sNTQUERYSECURITYATTRIBUTESTOKEN);
		break;
	case SP0_NTQUERYSECURITYOBJECT:
		strcpy(dest, sNTQUERYSECURITYOBJECT);
		break;
	case SP0_NTQUERYSEMAPHORE:
		strcpy(dest, sNTQUERYSEMAPHORE);
		break;
	case SP0_NTQUERYSYMBOLICLINKOBJECT:
		strcpy(dest, sNTQUERYSYMBOLICLINKOBJECT);
		break;
	case SP0_NTQUERYSYSTEMENVIRONMENTVALUE:
		strcpy(dest, sNTQUERYSYSTEMENVIRONMENTVALUE);
		break;
	case SP0_NTQUERYSYSTEMENVIRONMENTVALUEEX:
		strcpy(dest, sNTQUERYSYSTEMENVIRONMENTVALUEEX);
		break;
	case SP0_NTQUERYSYSTEMINFORMATION:
		strcpy(dest, sNTQUERYSYSTEMINFORMATION);
		break;
	case SP0_NTQUERYSYSTEMINFORMATIONEX:
		strcpy(dest, sNTQUERYSYSTEMINFORMATIONEX);
		break;
	case SP0_NTQUERYSYSTEMTIME:
		strcpy(dest, sNTQUERYSYSTEMTIME);
		break;
	case SP0_NTQUERYTIMER:
		strcpy(dest, sNTQUERYTIMER);
		break;
	case SP0_NTQUERYTIMERRESOLUTION:
		strcpy(dest, sNTQUERYTIMERRESOLUTION);
		break;
	case SP0_NTQUERYVALUEKEY:
		strcpy(dest, sNTQUERYVALUEKEY);
		break;
	case SP0_NTQUERYVIRTUALMEMORY:
		strcpy(dest, sNTQUERYVIRTUALMEMORY);
		break;
	case SP0_NTQUERYVOLUMEINFORMATIONFILE:
		strcpy(dest, sNTQUERYVOLUMEINFORMATIONFILE);
		break;
	case SP0_NTQUEUEAPCTHREAD:
		strcpy(dest, sNTQUEUEAPCTHREAD);
		break;
	case SP0_NTQUEUEAPCTHREADEX:
		strcpy(dest, sNTQUEUEAPCTHREADEX);
		break;
	case SP0_NTRAISEEXCEPTION:
		strcpy(dest, sNTRAISEEXCEPTION);
		break;
	case SP0_NTRAISEHARDERROR:
		strcpy(dest, sNTRAISEHARDERROR);
		break;
	case SP0_NTREADFILE:
		strcpy(dest, sNTREADFILE);
		break;
	case SP0_NTREADFILESCATTER:
		strcpy(dest, sNTREADFILESCATTER);
		break;
	case SP0_NTREADONLYENLISTMENT:
		strcpy(dest, sNTREADONLYENLISTMENT);
		break;
	case SP0_NTREADREQUESTDATA:
		strcpy(dest, sNTREADREQUESTDATA);
		break;
	case SP0_NTREADVIRTUALMEMORY:
		strcpy(dest, sNTREADVIRTUALMEMORY);
		break;
	case SP0_NTRECOVERENLISTMENT:
		strcpy(dest, sNTRECOVERENLISTMENT);
		break;
	case SP0_NTRECOVERRESOURCEMANAGER:
		strcpy(dest, sNTRECOVERRESOURCEMANAGER);
		break;
	case SP0_NTRECOVERTRANSACTIONMANAGER:
		strcpy(dest, sNTRECOVERTRANSACTIONMANAGER);
		break;
	case SP0_NTREGISTERPROTOCOLADDRESSINFORMATION:
		strcpy(dest, sNTREGISTERPROTOCOLADDRESSINFORMATION);
		break;
	case SP0_NTREGISTERTHREADTERMINATEPORT:
		strcpy(dest, sNTREGISTERTHREADTERMINATEPORT);
		break;
	case SP0_NTRELEASEKEYEDEVENT:
		strcpy(dest, sNTRELEASEKEYEDEVENT);
		break;
	case SP0_NTRELEASEMUTANT:
		strcpy(dest, sNTRELEASEMUTANT);
		break;
	case SP0_NTRELEASESEMAPHORE:
		strcpy(dest, sNTRELEASESEMAPHORE);
		break;
	case SP0_NTRELEASEWORKERFACTORYWORKER:
		strcpy(dest, sNTRELEASEWORKERFACTORYWORKER);
		break;
	case SP0_NTREMOVEIOCOMPLETION:
		strcpy(dest, sNTREMOVEIOCOMPLETION);
		break;
	case SP0_NTREMOVEIOCOMPLETIONEX:
		strcpy(dest, sNTREMOVEIOCOMPLETIONEX);
		break;
	case SP0_NTREMOVEPROCESSDEBUG:
		strcpy(dest, sNTREMOVEPROCESSDEBUG);
		break;
	case SP0_NTRENAMEKEY:
		strcpy(dest, sNTRENAMEKEY);
		break;
	case SP0_NTRENAMETRANSACTIONMANAGER:
		strcpy(dest, sNTRENAMETRANSACTIONMANAGER);
		break;
	case SP0_NTREPLACEKEY:
		strcpy(dest, sNTREPLACEKEY);
		break;
	case SP0_NTREPLACEPARTITIONUNIT:
		strcpy(dest, sNTREPLACEPARTITIONUNIT);
		break;
	case SP0_NTREPLYPORT:
		strcpy(dest, sNTREPLYPORT);
		break;
	case SP0_NTREPLYWAITRECEIVEPORT:
		strcpy(dest, sNTREPLYWAITRECEIVEPORT);
		break;
	case SP0_NTREPLYWAITRECEIVEPORTEX:
		strcpy(dest, sNTREPLYWAITRECEIVEPORTEX);
		break;
	case SP0_NTREPLYWAITREPLYPORT:
		strcpy(dest, sNTREPLYWAITREPLYPORT);
		break;
	case SP0_NTREQUESTPORT:
		strcpy(dest, sNTREQUESTPORT);
		break;
	case SP0_NTREQUESTWAITREPLYPORT:
		strcpy(dest, sNTREQUESTWAITREPLYPORT);
		break;
	case SP0_NTRESETEVENT:
		strcpy(dest, sNTRESETEVENT);
		break;
	case SP0_NTRESETWRITEWATCH:
		strcpy(dest, sNTRESETWRITEWATCH);
		break;
	case SP0_NTRESTOREKEY:
		strcpy(dest, sNTRESTOREKEY);
		break;
	case SP0_NTRESUMEPROCESS:
		strcpy(dest, sNTRESUMEPROCESS);
		break;
	case SP0_NTRESUMETHREAD:
		strcpy(dest, sNTRESUMETHREAD);
		break;
	case SP0_NTROLLBACKCOMPLETE:
		strcpy(dest, sNTROLLBACKCOMPLETE);
		break;
	case SP0_NTROLLBACKENLISTMENT:
		strcpy(dest, sNTROLLBACKENLISTMENT);
		break;
	case SP0_NTROLLBACKTRANSACTION:
		strcpy(dest, sNTROLLBACKTRANSACTION);
		break;
	case SP0_NTROLLFORWARDTRANSACTIONMANAGER:
		strcpy(dest, sNTROLLFORWARDTRANSACTIONMANAGER);
		break;
	case SP0_NTSAVEKEY:
		strcpy(dest, sNTSAVEKEY);
		break;
	case SP0_NTSAVEKEYEX:
		strcpy(dest, sNTSAVEKEYEX);
		break;
	case SP0_NTSAVEMERGEDKEYS:
		strcpy(dest, sNTSAVEMERGEDKEYS);
		break;
	case SP0_NTSECURECONNECTPORT:
		strcpy(dest, sNTSECURECONNECTPORT);
		break;
	case SP0_NTSERIALIZEBOOT:
		strcpy(dest, sNTSERIALIZEBOOT);
		break;
	case SP0_NTSETBOOTENTRYORDER:
		strcpy(dest, sNTSETBOOTENTRYORDER);
		break;
	case SP0_NTSETBOOTOPTIONS:
		strcpy(dest, sNTSETBOOTOPTIONS);
		break;
	case SP0_NTSETCONTEXTTHREAD:
		strcpy(dest, sNTSETCONTEXTTHREAD);
		break;
	case SP0_NTSETDEBUGFILTERSTATE:
		strcpy(dest, sNTSETDEBUGFILTERSTATE);
		break;
	case SP0_NTSETDEFAULTHARDERRORPORT:
		strcpy(dest, sNTSETDEFAULTHARDERRORPORT);
		break;
	case SP0_NTSETDEFAULTLOCALE:
		strcpy(dest, sNTSETDEFAULTLOCALE);
		break;
	case SP0_NTSETDEFAULTUILANGUAGE:
		strcpy(dest, sNTSETDEFAULTUILANGUAGE);
		break;
	case SP0_NTSETDRIVERENTRYORDER:
		strcpy(dest, sNTSETDRIVERENTRYORDER);
		break;
	case SP0_NTSETEAFILE:
		strcpy(dest, sNTSETEAFILE);
		break;
	case SP0_NTSETEVENT:
		strcpy(dest, sNTSETEVENT);
		break;
	case SP0_NTSETEVENTBOOSTPRIORITY:
		strcpy(dest, sNTSETEVENTBOOSTPRIORITY);
		break;
	case SP0_NTSETHIGHEVENTPAIR:
		strcpy(dest, sNTSETHIGHEVENTPAIR);
		break;
	case SP0_NTSETHIGHWAITLOWEVENTPAIR:
		strcpy(dest, sNTSETHIGHWAITLOWEVENTPAIR);
		break;
	case SP0_NTSETINFORMATIONDEBUGOBJECT:
		strcpy(dest, sNTSETINFORMATIONDEBUGOBJECT);
		break;
	case SP0_NTSETINFORMATIONENLISTMENT:
		strcpy(dest, sNTSETINFORMATIONENLISTMENT);
		break;
	case SP0_NTSETINFORMATIONFILE:
		strcpy(dest, sNTSETINFORMATIONFILE);
		break;
	case SP0_NTSETINFORMATIONJOBOBJECT:
		strcpy(dest, sNTSETINFORMATIONJOBOBJECT);
		break;
	case SP0_NTSETINFORMATIONKEY:
		strcpy(dest, sNTSETINFORMATIONKEY);
		break;
	case SP0_NTSETINFORMATIONOBJECT:
		strcpy(dest, sNTSETINFORMATIONOBJECT);
		break;
	case SP0_NTSETINFORMATIONPROCESS:
		strcpy(dest, sNTSETINFORMATIONPROCESS);
		break;
	case SP0_NTSETINFORMATIONRESOURCEMANAGER:
		strcpy(dest, sNTSETINFORMATIONRESOURCEMANAGER);
		break;
	case SP0_NTSETINFORMATIONTHREAD:
		strcpy(dest, sNTSETINFORMATIONTHREAD);
		break;
	case SP0_NTSETINFORMATIONTOKEN:
		strcpy(dest, sNTSETINFORMATIONTOKEN);
		break;
	case SP0_NTSETINFORMATIONTRANSACTION:
		strcpy(dest, sNTSETINFORMATIONTRANSACTION);
		break;
	case SP0_NTSETINFORMATIONTRANSACTIONMANAGER:
		strcpy(dest, sNTSETINFORMATIONTRANSACTIONMANAGER);
		break;
	case SP0_NTSETINFORMATIONWORKERFACTORY:
		strcpy(dest, sNTSETINFORMATIONWORKERFACTORY);
		break;
	case SP0_NTSETINTERVALPROFILE:
		strcpy(dest, sNTSETINTERVALPROFILE);
		break;
	case SP0_NTSETIOCOMPLETION:
		strcpy(dest, sNTSETIOCOMPLETION);
		break;
	case SP0_NTSETIOCOMPLETIONEX:
		strcpy(dest, sNTSETIOCOMPLETIONEX);
		break;
	case SP0_NTSETLOWEVENTPAIR:
		strcpy(dest, sNTSETLOWEVENTPAIR);
		break;
	case SP0_NTSETLOWWAITHIGHEVENTPAIR:
		strcpy(dest, sNTSETLOWWAITHIGHEVENTPAIR);
		break;
	case SP0_NTSETQUOTAINFORMATIONFILE:
		strcpy(dest, sNTSETQUOTAINFORMATIONFILE);
		break;
	case SP0_NTSETSECURITYOBJECT:
		strcpy(dest, sNTSETSECURITYOBJECT);
		break;
	case SP0_NTSETSYSTEMENVIRONMENTVALUE:
		strcpy(dest, sNTSETSYSTEMENVIRONMENTVALUE);
		break;
	case SP0_NTSETSYSTEMENVIRONMENTVALUEEX:
		strcpy(dest, sNTSETSYSTEMENVIRONMENTVALUEEX);
		break;
	case SP0_NTSETSYSTEMINFORMATION:
		strcpy(dest, sNTSETSYSTEMINFORMATION);
		break;
	case SP0_NTSETSYSTEMPOWERSTATE:
		strcpy(dest, sNTSETSYSTEMPOWERSTATE);
		break;
	case SP0_NTSETSYSTEMTIME:
		strcpy(dest, sNTSETSYSTEMTIME);
		break;
	case SP0_NTSETTHREADEXECUTIONSTATE:
		strcpy(dest, sNTSETTHREADEXECUTIONSTATE);
		break;
	case SP0_NTSETTIMER:
		strcpy(dest, sNTSETTIMER);
		break;
	case SP0_NTSETTIMEREX:
		strcpy(dest, sNTSETTIMEREX);
		break;
	case SP0_NTSETTIMERRESOLUTION:
		strcpy(dest, sNTSETTIMERRESOLUTION);
		break;
	case SP0_NTSETUUIDSEED:
		strcpy(dest, sNTSETUUIDSEED);
		break;
	case SP0_NTSETVALUEKEY:
		strcpy(dest, sNTSETVALUEKEY);
		break;
	case SP0_NTSETVOLUMEINFORMATIONFILE:
		strcpy(dest, sNTSETVOLUMEINFORMATIONFILE);
		break;
	case SP0_NTSHUTDOWNSYSTEM:
		strcpy(dest, sNTSHUTDOWNSYSTEM);
		break;
	case SP0_NTSHUTDOWNWORKERFACTORY:
		strcpy(dest, sNTSHUTDOWNWORKERFACTORY);
		break;
	case SP0_NTSIGNALANDWAITFORSINGLEOBJECT:
		strcpy(dest, sNTSIGNALANDWAITFORSINGLEOBJECT);
		break;
	case SP0_NTSINGLEPHASEREJECT:
		strcpy(dest, sNTSINGLEPHASEREJECT);
		break;
	case SP0_NTSTARTPROFILE:
		strcpy(dest, sNTSTARTPROFILE);
		break;
	case SP0_NTSTOPPROFILE:
		strcpy(dest, sNTSTOPPROFILE);
		break;
	case SP0_NTSUSPENDPROCESS:
		strcpy(dest, sNTSUSPENDPROCESS);
		break;
	case SP0_NTSUSPENDTHREAD:
		strcpy(dest, sNTSUSPENDTHREAD);
		break;
	case SP0_NTSYSTEMDEBUGCONTROL:
		strcpy(dest, sNTSYSTEMDEBUGCONTROL);
		break;
	case SP0_NTTERMINATEJOBOBJECT:
		strcpy(dest, sNTTERMINATEJOBOBJECT);
		break;
	case SP0_NTTERMINATEPROCESS:
		strcpy(dest, sNTTERMINATEPROCESS);
		break;
	case SP0_NTTERMINATETHREAD:
		strcpy(dest, sNTTERMINATETHREAD);
		break;
	case SP0_NTTESTALERT:
		strcpy(dest, sNTTESTALERT);
		break;
	case SP0_NTTHAWREGISTRY:
		strcpy(dest, sNTTHAWREGISTRY);
		break;
	case SP0_NTTHAWTRANSACTIONS:
		strcpy(dest, sNTTHAWTRANSACTIONS);
		break;
	case SP0_NTTRACECONTROL:
		strcpy(dest, sNTTRACECONTROL);
		break;
	case SP0_NTTRACEEVENT:
		strcpy(dest, sNTTRACEEVENT);
		break;
	case SP0_NTTRANSLATEFILEPATH:
		strcpy(dest, sNTTRANSLATEFILEPATH);
		break;
	case SP0_NTUMSTHREADYIELD:
		strcpy(dest, sNTUMSTHREADYIELD);
		break;
	case SP0_NTUNLOADDRIVER:
		strcpy(dest, sNTUNLOADDRIVER);
		break;
	case SP0_NTUNLOADKEY:
		strcpy(dest, sNTUNLOADKEY);
		break;
	case SP0_NTUNLOADKEY2:
		strcpy(dest, sNTUNLOADKEY2);
		break;
	case SP0_NTUNLOADKEYEX:
		strcpy(dest, sNTUNLOADKEYEX);
		break;
	case SP0_NTUNLOCKFILE:
		strcpy(dest, sNTUNLOCKFILE);
		break;
	case SP0_NTUNLOCKVIRTUALMEMORY:
		strcpy(dest, sNTUNLOCKVIRTUALMEMORY);
		break;
	case SP0_NTUNMAPVIEWOFSECTION:
		strcpy(dest, sNTUNMAPVIEWOFSECTION);
		break;
	case SP0_NTVDMCONTROL:
		strcpy(dest, sNTVDMCONTROL);
		break;
	case SP0_NTWAITFORDEBUGEVENT:
		strcpy(dest, sNTWAITFORDEBUGEVENT);
		break;
	case SP0_NTWAITFORKEYEDEVENT:
		strcpy(dest, sNTWAITFORKEYEDEVENT);
		break;
	case SP0_NTWAITFORMULTIPLEOBJECTS:
		strcpy(dest, sNTWAITFORMULTIPLEOBJECTS);
		break;
	case SP0_NTWAITFORMULTIPLEOBJECTS32:
		strcpy(dest, sNTWAITFORMULTIPLEOBJECTS32);
		break;
	case SP0_NTWAITFORSINGLEOBJECT:
		strcpy(dest, sNTWAITFORSINGLEOBJECT);
		break;
	case SP0_NTWAITFORWORKVIAWORKERFACTORY:
		strcpy(dest, sNTWAITFORWORKVIAWORKERFACTORY);
		break;
	case SP0_NTWAITHIGHEVENTPAIR:
		strcpy(dest, sNTWAITHIGHEVENTPAIR);
		break;
	case SP0_NTWAITLOWEVENTPAIR:
		strcpy(dest, sNTWAITLOWEVENTPAIR);
		break;
	case SP0_NTWORKERFACTORYWORKERREADY:
		strcpy(dest, sNTWORKERFACTORYWORKERREADY);
		break;
	case SP0_NTWRITEFILE:
		strcpy(dest, sNTWRITEFILE);
		break;
	case SP0_NTWRITEFILEGATHER:
		strcpy(dest, sNTWRITEFILEGATHER);
		break;
	case SP0_NTWRITEREQUESTDATA:
		strcpy(dest, sNTWRITEREQUESTDATA);
		break;
	case SP0_NTWRITEVIRTUALMEMORY:
		strcpy(dest, sNTWRITEVIRTUALMEMORY);
		break;
	case SP0_NTYIELDEXECUTION:
		strcpy(dest, sNTYIELDEXECUTION);
		break;
	case SP0_XHALGETINTERRUPTTRANSLATOR:
		strcpy(dest, sXHALGETINTERRUPTTRANSLATOR);
		break;
	case SP0_XKDSETUPPCIDEVICEFORDEBUGGING:
		strcpy(dest, sXKDSETUPPCIDEVICEFORDEBUGGING);
		break;
	default:
		break;

	}
}

void init_hist(syscall_hist *sh)
{
	sh->array = (unsigned short*)malloc(BASE_HIST_ARRAY_SIZE * sizeof(unsigned short));
	sh->count = 0;
	sh->next = NULL;
}

static inline void add_item(syscall_hist *sh, unsigned short callno)
{
	if (sh->count % BASE_HIST_ARRAY_SIZE == 0 && sh->count != 0)
	{
		sh->array = (unsigned short*)realloc(sh->array, (sh->count + BASE_HIST_ARRAY_SIZE) * sizeof(unsigned short));
	}

	*(sh->array + sh->count) = callno;

	sh->count++;
}

char* find_executable(int argc, char *argv[])
{
	int pos;
	char *spos = NULL;

	for(pos=0;pos<argc;pos++)
	{
		if(strcmp("--",argv[pos]) == 0)
			break;
	}

	if((pos + 1) < argc)
	{
		int last_slash = -1;
		unsigned int i;
		pos++;
		for(i=0;i<strlen(argv[pos]);i++)
		{
			if(argv[pos][i] == '/')
				last_slash = i;
		}

//		if(last_slash != -1)
			spos = argv[pos] + last_slash + 1 ;
	}

	return spos;

}

/*FILE* open_output_file(char *output_fmt, char *logPath, char *base_name)
{
	char fullPath[1024];
	OS_FILE_ATTRIBUTES finfo;
	
	sprintf(fullPath, "%sstrace2_%s.out", logPath, main_exe);
	trace2 = fopen(fullPath, "wb");
}
*/

int get_main_iter(char *logPath, char *base_name, int *fd)
{
	char fullPath[1024];
	int iteration = 0;
	int ver_file = -1;

	while(ver_file == -1)
	{
		sprintf(fullPath, "%slock_%s_%d.out", logPath, base_name,iteration);
		ver_file = open(fullPath,O_CREAT|O_EXCL|O_RDWR,S_IRWXU|S_IRWXG|S_IRWXO);

		if(ver_file != -1)
			break;
		else
			iteration++;
	}

	*fd = ver_file;
	return iteration;
}

char* clean_hash_string(char *s)
{
	char *pos;

	if(s == NULL || s[0] == '\0')
		return s;

	s[PR_MAX-1] = '\0';

	pos = s + strlen(s) - 1;

	for(;pos >= s && isblank(*pos); pos--);

	if(pos < s)
		return s;
	else if((pos - s) < PR_MAX-1)
		*(pos + 1) = '\0';

	pos = rindex(s,'#');

	if(pos == NULL)
		return s;

	pos--;

	for(;pos >= s && isblank(*pos); pos--);

	if(pos < s)
		return s;
	else if((pos - s) < PR_MAX-1)
		*(pos + 1) = '\0';

	return s;
}
