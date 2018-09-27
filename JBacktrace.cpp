//
// Created by jiangjh on 2018/9/27.
//

#include <iostream>
#include <iomanip>

#include <unwind.h>
#include <dlfcn.h>
#include <sstream>
#include <fb/ALog.h>


namespace {

    struct BacktraceState
    {
        void** current;
        void** end;
    };

    static _Unwind_Reason_Code unwindCallback(struct _Unwind_Context* context, void* arg)
    {
        BacktraceState* state = static_cast<BacktraceState*>(arg);
        uintptr_t pc = _Unwind_GetIP(context);
        if (pc) {
            if (state->current == state->end) {
                return _URC_END_OF_STACK;
            } else {
                *state->current++ = reinterpret_cast<void*>(pc);
            }
        }
        return _URC_NO_REASON;
    }

}

size_t captureBacktrace(void** buffer, size_t max)
{
    BacktraceState state = {buffer, buffer + max};
    _Unwind_Backtrace(unwindCallback, &state);

    return state.current - buffer;
}

void dumpBacktrace(std::ostream& os, void** buffer, size_t count, uint8_t* moduleAddr)
{
    for (size_t idx = 0; idx < count; ++idx) {
        const void* addr = buffer[idx];
        const char* symbol = "";
        char offset[24] = {0};

        Dl_info info;
        if (dladdr(addr, &info) && info.dli_sname) {
            symbol = info.dli_sname;
        }else{
            int relativeAddr = (uint)addr - (uint)moduleAddr;
            if (relativeAddr < 0x10000000){
                sprintf(offset,"-->0x%08x",relativeAddr);
            }
        }

        if(strcmp(symbol,"") != 0){
            os << "  #" << std::setw(2) << idx << ": " << addr << "  " << symbol << "\n";
        }else if(offset[0] != 0){
            os << "  #" << std::setw(2) << idx << ": " << addr << "  " << offset << "\n";
        }else{
            os << "  #" << std::setw(2) << idx << ": " << addr << "  " << "\n";
        }

    }
}

void backtraceToLogcat(char *tag,uint8_t* moduleAddr){
    const size_t max = 15;
    void* buffer[max];
    std::ostringstream oss;

    dumpBacktrace(oss, buffer, captureBacktrace(buffer, max),moduleAddr);

    MYLOGD("TAG:%s  --> \n %s",tag,oss.str().c_str());
}