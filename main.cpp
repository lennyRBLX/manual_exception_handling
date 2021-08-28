#include "memory.h"

/*
	this will only be noticable inside of modules that have no previous exception handling support
	a good example of this would be something like a manually mapped module

	IMPORTANT
	as a manually mapped module, if you remain inside a module that already has exception handling you will have to
	run memory::remove_inverted_func_table() with the parameter being the base address of the module with exception handling in order
	to allow you to get exception handling

	WHY THIS WORKS - __try & __except
	reversed by BlackBone's dev DarthTon he found that by placing your module inside the global LdrpInvertedFunctionTable you can obtain
	exception handling without having to handle it inside VEH, however i made sure this was the case by placing VEH that would go through
	the handlers of the module told to be handled by memory::enable_exceptions and determine if there is a handler for the exception
	being sent to the VEH

	i took hints from the ehdata.h file and some basic memory research to see how gathering all the necessary information for the loop
	to be successful, heres a simple breakdown of what it does:

	exception_table[i] -> unwind_info -> frame_count & exception_data_ptr -> (exception address inside handler) && (is a Exception HANDLER or a Unhandled HANDLER) ->
	frames[ii] -> exception_frame_offset -> exception_frame & frame_start_offset & frame_end_offset -> (exception address inside frame) ->
	SetLastError & jmp to exception_frame

	WHY THIS WORKS - c++
	this wasn't very reversed or looked into by people but without the extra details ill just go directly into why this works
	i place an IAT (Import Address Table) hook on RaiseException which is called to handle c++ exceptions, the function that does is called
	__CxxThrowException and can be found under the symbols for any compiled module, this function is called with the same exception that
	can be used to identify c++ exceptions in the VEH and this exception code can be found under the definition EH_EXCEPTION_NUMBER which is
	inside ehdata.h

	by using this i can go through the call stack of RaiseException and, making sure to check the callstack is for the most recent exception, i
	can see if any of the functions in the callstack have a handler by going through the exception_table, after checking if there is a handler
	i then call the language_handler discovered by looking for the function entry via RtlLookupFunctionEntry as well as RtlVirtualUnwind
	after all of this is done i call the language handler to make sure it does get called and handles the exception properly, even if the c++
	exception handling code fails

	call_stack[i] -> exception_table[ii] -> unwind_info -> (exception address inside handler) && (is a Exception HANDLER or a Unhandled HANDLER) ->
	function_entry & handler_data & establisher_frame & language_handler -> return language_handler(necessary data)

	FINAL NOTES
	this should work for any exceptions inside the current module, but this is untested to work with exceptions coming from exterior modules that should be handled
	inside this module, ex. calling a function that triggers __except and should be handled inside the current module
*/

int main(int argc, char* argv[]) {
	memory::enable_exceptions(GetModuleHandleA(NULL)); // past this point your exceptions will work as normal
}