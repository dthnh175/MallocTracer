#include "pin.h"
#include <iostream>
#include <fstream>
#include <map>

using namespace std;

map<ADDRINT, bool> MallocMap; // true means address been deallocated, false mean not deallocated.
ofstream LogFile;
KNOB<string> LogFileName(KNOB_MODE_WRITEONCE, "pintool", "o", "MallocTracer.log", "Memory trace file name");

VOID LogBeforeMalloc(ADDRINT size) {
	LogFile << "[*] malloc(" << dec << size << ")" << endl;
}

VOID LogAfterMalloc(ADDRINT addr) {
	if (addr == NULL) {
		cerr << "[-] Error: malloc() returned NULL. Heap full??";
		return;
	}

	map<ADDRINT, bool>::iterator it = MallocMap.find(addr);

	if (it != MallocMap.end()) {
		if (it->second == true) {
			it->second = false;
		}
		else {
			cerr << "[-] ERROR: allocated memory not freed" << endl;
		}
	}
	else {
		MallocMap.insert(pair<ADDRINT, bool>(addr, false));
		LogFile << "\t\t= 0x" << hex << addr << endl;
	}
}

VOID LogFree(ADDRINT addr) {	
	if (MallocMap.count(addr) > 0) {
		map<ADDRINT, bool>::iterator it = MallocMap.find(addr);
		if (it->second == true) {
			LogFile << "[*] Memory address 0x" << hex << addr << " was freed more than once." << endl;
		}
		else {
			it->second = true;
			LogFile << "[*] free(0x" << hex << addr << ")" << endl;
		}
	}
	else {
		LogFile << "[*] Freeing unallocated memory address 0x" << hex << addr << "." << endl;
	}
}

VOID CustomInstrumentation(IMG img, VOID* v) {
	for (SYM sym = IMG_RegsymHead(img); SYM_Valid(sym); sym = SYM_Next(sym)) {
		string undFuncName = PIN_UndecorateSymbolName(SYM_Name(sym), UNDECORATION_NAME_ONLY);
		if (undFuncName == "malloc") {
			RTN allocRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym)); // function "malloc" address
			if (RTN_Valid(allocRtn)) {
				RTN_Open(allocRtn);
				RTN_InsertCall(allocRtn, IPOINT_BEFORE, (AFUNPTR)LogBeforeMalloc,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END); // malloc size
				RTN_InsertCall(allocRtn, IPOINT_AFTER, (AFUNPTR)LogAfterMalloc,
					IARG_FUNCRET_EXITPOINT_VALUE, IARG_END); // malloc return address
				RTN_Close(allocRtn);
			}
		}
		else if (undFuncName == "free") {
			RTN freeRtn = RTN_FindByAddress(IMG_LowAddress(img) + SYM_Value(sym)); // function "free" address
			if (RTN_Valid(freeRtn)) {
				RTN_Open(freeRtn);
				RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)LogFree,
					IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END); // address to be freed
				RTN_Close(freeRtn);
			}
		}
	}
}

VOID FinalFunc(INT32 code, VOID* v) {
	for (pair<ADDRINT, bool> p : MallocMap) {
		if (!p.second) {
			LogFile << "[*] Memory at address 0x" << hex << p.first << " allocated but not freed." << endl;
		}
	}
	LogFile.close();
}

int main(int argc, char* argv[]) {
	PIN_InitSymbols();
	PIN_Init(argc, argv);
	LogFile.open(LogFileName.Value().c_str());
	IMG_AddInstrumentFunction(CustomInstrumentation, NULL);
	PIN_AddFiniFunction(FinalFunc, NULL);
	PIN_StartProgram();

	return 0;
}