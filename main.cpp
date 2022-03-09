#include <typeinfo>
#include <exception>
#include <dlfcn.h>
#include <pthread.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <execinfo.h>
#include <cxxabi.h>
#include <unwind.h>
#include <unistd.h>
#include <cassert>
#include <elfutils/libdwfl.h> // Dwfl*
#include <string>
#include <memory>
#include <sstream>
#include <iostream>

std::string demangle(const char* name) {
    int status = -4;
    std::unique_ptr<char, void(*)(void*)> res {
        abi::__cxa_demangle(name, NULL, NULL, &status),
        std::free
    };
    return (status==0) ? res.get() : name ;
}

std::string debug_info(Dwfl* dwfl, void* ip) {
    std::string function;
    int line = -1;
    char const* file;
    uintptr_t ip2 = reinterpret_cast<uintptr_t>(ip);
    Dwfl_Module* module = dwfl_addrmodule(dwfl, ip2);
    char const* name = dwfl_module_addrname(module, ip2);
    function = name ? demangle(name) : "<unknown>";
    if (Dwfl_Line* dwfl_line = dwfl_module_getsrc(module, ip2)) {
        Dwarf_Addr addr;
        file = dwfl_lineinfo(dwfl_line, &addr, &line, nullptr, nullptr, nullptr);
    }
    std::stringstream ss;
    ss << ip << ' ' << function;
    if (file)
        ss << " at " << file << ':' << line;
    ss << std::endl;
    return ss.str();
}


std::string stacktrace() {
    // Initialize Dwfl.
    Dwfl* dwfl = nullptr;
    {
        Dwfl_Callbacks callbacks = {};
        char* debuginfo_path = nullptr;
        callbacks.find_elf = dwfl_linux_proc_find_elf;
        callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
        callbacks.debuginfo_path = &debuginfo_path;
        dwfl = dwfl_begin(&callbacks);
        assert(dwfl);
        int r;
        r = dwfl_linux_proc_report(dwfl, getpid());
        assert(!r);
        r = dwfl_report_end(dwfl, nullptr, nullptr);
        assert(!r);
        static_cast<void>(r);
    }

    // Loop over stack frames.
    std::stringstream ss;
    {
        void* stack[512];
        int stack_size = ::backtrace(stack, sizeof stack / sizeof *stack);
        for (int i = 0; i < stack_size; ++i) {
            ss << i << ": ";

            // Works.
            ss << debug_info(dwfl, stack[i]);

#if 0
            // TODO intended to do the same as above, but segfaults,
            // so possibly UB In above function that does not blow up by chance?
            void *ip = stack[i];
            std::string function;
            int line = -1;
            char const* file;
            uintptr_t ip2 = reinterpret_cast<uintptr_t>(ip);
            Dwfl_Module* module = dwfl_addrmodule(dwfl, ip2);
            char const* name = dwfl_module_addrname(module, ip2);
            function = name ? demangle(name) : "<unknown>";
            // TODO if I comment out this line it does not blow up anymore.
            if (Dwfl_Line* dwfl_line = dwfl_module_getsrc(module, ip2)) {
              Dwarf_Addr addr;
              file = dwfl_lineinfo(dwfl_line, &addr, &line, nullptr, nullptr, nullptr);
            }
            ss << ip << ' ' << function;
            if (file)
                ss << " at " << file << ':' << line;
            ss << std::endl;
#endif
        }
    }
    dwfl_end(dwfl);
    return ss.str();
}

struct __cxa_exception {
	std::type_info* exceptionType;
	void (*exceptionDestructor)(void*);
	std::unexpected_handler unexpectedHandler;
	std::terminate_handler terminateHandler;
	__cxa_exception* nextException;
	int handlerCount;
	int handlerSwitchValue;
	const char* actionRecord;
	const char* languageSpecificData;
	void* catchTemp;
	void* adjustedPtr;
	_Unwind_Exception unwindHeader;
};

struct __cxa_eh_globals {
	__cxa_exception* caughtExceptions;
	unsigned int uncaughtExceptions;
};

extern "C" __cxa_eh_globals* __cxa_get_globals(void);

using cxa_throw_type   = void(*)(void*, std::type_info*, void(*)(void*));
using cxa_rethrow_type = void(*)();

static cxa_throw_type   orig_cxa_throw   = nullptr; // Address of the original __cxa_throw
static cxa_rethrow_type orig_cxa_rethrow = nullptr; // Address of the original __cxa_rethrow

/**
 * Get the backtrace.
 * Here and below we use functions from the C library; these functions do not throw exceptions.
 */
static void get_backtrace()
{
	static void* buf[128];

	int n = backtrace(buf, 128);
	std::fprintf(stderr, "%s\n", "*** BACKTRACE ***");
	backtrace_symbols_fd(buf, n, STDERR_FILENO);
}

/**
 * Exception handling common for both __cxa_throw and __cxa_rethrow
 */
static void handle_exception(void* thrown_exception, std::type_info* tinfo, bool rethrown)
{
	char* demangled = abi:: __cxa_demangle(tinfo->name(), 0, 0, 0);
	std::fprintf(stderr, "%s exception of type %s\n", (rethrown ? "Rethrown" : "Thrown"), (demangled ? demangled : tinfo->name()));
	if (demangled) {
		std::free(demangled);
	}

	const abi::__class_type_info* exc = dynamic_cast<const abi::__class_type_info*>(&typeid(std::exception));
	const abi::__class_type_info* cti = dynamic_cast<abi::__class_type_info*>(tinfo);

	if (cti && exc) {
		std::exception* the_exception = reinterpret_cast<std::exception*>(abi::__dynamic_cast(thrown_exception, exc, cti, -1));
		if (the_exception) {
			std::fprintf(stderr, "what(): %s\n", the_exception->what());
		}
	}

	//get_backtrace();
	std::cout << stacktrace() << std::endl;
	std::fprintf(stderr, "\n\n");
}

// The functions below should go to an anonymous namespace, otherwise g++ becomes crazy and complains about
// mismatched types in throw statements
namespace {

extern "C" void __cxa_throw(void* thrown_exception, std::type_info* tinfo, void (*dest)(void*))
{
	handle_exception(thrown_exception, tinfo, false);

	if (orig_cxa_throw) {
		orig_cxa_throw(thrown_exception, tinfo, dest);
	}
	else {
		std::terminate();
	}
}

extern "C" void __cxa_rethrow(void)
{
	__cxa_eh_globals* g = __cxa_get_globals();
	if (g && g->caughtExceptions) {
		void* thrown_exception = reinterpret_cast<uint8_t*>(g->caughtExceptions) + sizeof(struct __cxa_exception);
		handle_exception(thrown_exception, g->caughtExceptions->exceptionType, true);
	}

	if (orig_cxa_rethrow) {
		orig_cxa_rethrow();
	}
	else {
		std::terminate();
	}
}

}

/**
 * Initialization. This can probably be done from the exception handler.
 */
static void initialize()
{
	orig_cxa_throw   = reinterpret_cast<cxa_throw_type>(dlsym(RTLD_NEXT, "__cxa_throw"));
	orig_cxa_rethrow = reinterpret_cast<cxa_rethrow_type>(dlsym(RTLD_NEXT, "__cxa_rethrow"));
}

int main(int, char**)
{
	initialize();


	try {
		try {
			throw std::runtime_error("123");
		}
		catch (const std::exception& e) {
			std::printf("e.what(): %s\n", e.what());
			throw;
		}
	}
	catch (const std::exception& d) {
		std::printf("d.what(): %s\n", d.what());
	}

	try {
		throw 1;
	}
	catch (int x) {
		std::printf("%d\n", x);
	}

	std::cout << "finish" << std::endl;
	return 0;
}

