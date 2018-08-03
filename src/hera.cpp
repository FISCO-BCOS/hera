/*
 * Copyright 2016-2018 Alex Beregszaszi et al.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <hera/hera.h>

#include <vector>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>
#include <string.h>
#include <fstream>

#include <pass.h>
#include <wasm.h>
#include <wasm-binary.h>
#include <wasm-builder.h>
#include <wasm-interpreter.h>
#include <wasm-printing.h>
#include <wasm-validator.h>

#include <evmc/evmc.h>

#include <evm2wasm.h>

#include "eei.h"
#include "exceptions.h"

#include <hera/buildinfo.h>

using namespace std;
using namespace wasm;
using namespace hera;

enum class hera_wasm_engine {
  binaryen,
  wavm,
  wabt
};

enum class hera_evm_mode {
  reject,
  fallback,
  evm2wasm_contract,
  evm2wasm_cpp,
  evm2wasm_cpp_tracing,
  evm2wasm_js,
  evm2wasm_js_tracing
};

struct hera_instance : evmc_instance {
  hera_wasm_engine wasm_engine = hera_wasm_engine::binaryen;
  hera_evm_mode evm_mode = hera_evm_mode::reject;
  bool metering = false;
  vector<pair<evmc_address, string>> contract_preload_list;

  hera_instance() noexcept : evmc_instance({EVMC_ABI_VERSION, "hera", hera_get_buildinfo()->project_version, nullptr, nullptr, nullptr, nullptr}) {}
};

namespace {

const evmc_address sentinelAddress = { .bytes = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa } };
const evmc_address evm2wasmAddress = { .bytes = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb } };

bool hasWasmPreamble(vector<uint8_t> const& _input) {
  return
    _input.size() >= 8 &&
    _input[0] == 0 &&
    _input[1] == 'a' &&
    _input[2] == 's' &&
    _input[3] == 'm' &&
    _input[4] == 1 &&
    _input[5] == 0 &&
    _input[6] == 0 &&
    _input[7] == 0;
}

#if HERA_DEBUGGING
//Returns a formatted string (with prefix "0x") representing the bytes of an array.
string bytesAsHexStr(const uint8_t *bytes, const size_t length) {
  stringstream ret;
  ret << hex << "0x";

  for (size_t i = 0; i < length; ++i) {
    ret << setw(2) << setfill('0') << (int)bytes[i];
  }

  return ret.str();
}

void debugPrintPreloadList(const hera_instance* hera) {
  auto const& list = hera->contract_preload_list;

  cerr << "DEBUG: Preload list contents" << endl;
  if (list.size() == 0) {
    cerr << "List is empty!" << endl;
    return;
  }

  for (size_t i = 0; i < list.size(); ++i) {
    cerr << i << ": " << bytesAsHexStr(list[i].first.bytes, 20) << " => " << list[i].second << endl;
  }
}
#endif

//Resolve an address on the preload list to a filepath containing the binary.
//This assumes that the address is on the list, implying resolveSystemContract has been called.
string resolvePreloadPath(const evmc_address* addr, const hera_instance *hera) {
  auto const& list = hera->contract_preload_list;

  for (size_t i = 0; i < list.size(); ++i) {
    if (memcmp(list[i].first.bytes, addr->bytes, sizeof(evmc_address)) == 0) {
#if HERA_DEBUGGING
      cerr << "Successfully resolved address " << bytesAsHexStr(addr->bytes, 20) << " to filepath " << list[i].second << endl;
#endif
      return string(list[i].second);
    }  
  }

  heraAssert(false, "The specified address could not be resolved to a filepath with its binary.");
}

//Returns the bytecode to be overridden before execution
vector<uint8_t> overrideRunCode(const evmc_address *addr, const hera_instance *hera) {
  const string path = resolvePreloadPath(addr, hera);

#if HERA_DEBUGGING
  cerr << "Attempting to load file " << path << endl;
#endif
  ifstream fp;
  fp.open(path.c_str(), ios::in | ios::binary);

  if (!fp.is_open()) throw InternalErrorException(string("Failed to open WASM binary"));
  
  istreambuf_iterator<char> fp_start(fp), fp_end;
  vector<char> bytecode(fp_start, fp_end);
#if HERA_DEBUGGING
  cerr << "Successfully loaded file " << path << endl;
#endif
  //Replace the run code with the loaded bytecode
  return vector<uint8_t>(bytecode.begin(), bytecode.end());
}

//Checks if the contract preload list contains the given address.
bool resolveSystemContract(const hera_instance *hera, const evmc_address *addr) {
  auto const& list = hera->contract_preload_list;

  for (size_t i = 0; i < list.size(); ++i) {
    if (memcmp(list[i].first.bytes, addr->bytes, sizeof(evmc_address)) == 0) {
#if HERA_DEBUGGING
      cerr << "Successfully resolved address " << bytesAsHexStr(addr->bytes, 20) << endl;
#endif
      return true;
    }   
  }
  
#if HERA_DEBUGGING
  cerr << "Address does not match " << bytesAsHexStr(addr->bytes, 20) << endl;
#endif
  return false;
}

// Calls a system contract at @address with input data @input.
// It is a "staticcall" with sender 000...000 and no value.
// @returns output data from the contract and update the @gas variable with the gas left.
vector<uint8_t> callSystemContract(
  evmc_context* context,
  evmc_address const& address,
  int64_t & gas,
  vector<uint8_t> const& input
) {
  evmc_message message = {
    .destination = address,
    .sender = {},
    .value = {},
    .input_data = input.data(),
    .input_size = input.size(),
    .code_hash = {},
    .create2_salt = {},
    .gas = gas,
    .depth = 0,
    .kind = EVMC_CALL,
    .flags = EVMC_STATIC
  };

  evmc_result result;
  context->fn_table->call(&result, context, &message);

  vector<uint8_t> ret;
  if (result.status_code == EVMC_SUCCESS && result.output_data)
    ret.assign(result.output_data, result.output_data + result.output_size);

  gas = result.gas_left;

  if (result.release)
    result.release(&result);

  return ret;
}

// Calls the Sentinel contract with input data @input.
// @returns the validated and metered output or empty output otherwise.
vector<uint8_t> sentinel(evmc_context* context, vector<uint8_t> const& input)
{
#if HERA_DEBUGGING
  cerr << "Metering (input " << input.size() << " bytes)..." << endl;
#endif

  int64_t startgas = numeric_limits<int64_t>::max(); // do not charge for metering yet (give unlimited gas)
  int64_t gas = startgas;
  vector<uint8_t> ret = callSystemContract(
    context,
    sentinelAddress,
    gas,
    input
  );

#if HERA_DEBUGGING
  cerr << "Metering done (output " << ret.size() << " bytes, used " << (startgas - gas) << " gas)" << endl;
#endif

  return ret;
}

// NOTE: assumes that pattern doesn't contain any formatting characters (e.g. %)
string mktemp_string(string pattern) {
  const unsigned long len = pattern.size();
  char tmp[len + 1];
  strcpy(tmp, pattern.data());
  if (!mktemp(tmp) || (tmp[0] == 0))
     return string();
  return string(tmp, strlen(tmp));
}

// Calls evm2wasm (as a Javascript CLI) with input data @input.
// @returns the compiled output or empty output otherwise.
vector<uint8_t> evm2wasm_js(vector<uint8_t> const& input, bool evmTrace) {
#if HERA_DEBUGGING
  cerr << "Calling evm2wasm.js (input " << input.size() << " bytes)..." << endl;
#endif

  string fileEVM = mktemp_string("/tmp/hera.evm2wasm.evm.XXXXXX");
  string fileWASM = mktemp_string("/tmp/hera.evm2wasm.wasm.XXXXXX");

  if (fileEVM.size() == 0 || fileWASM.size() == 0)
    return vector<uint8_t>();

  ofstream os;
  os.open(fileEVM);
  // print as a hex sting
  os << hex;
  for (uint8_t byte: input)
    os << setfill('0') << setw(2) << static_cast<int>(byte);
  os.close();

  string cmd = string("evm2wasm.js ") + "-e " + fileEVM + " -o " + fileWASM + " --charge-per-op";
  if (evmTrace)
    cmd += " --trace";

#if HERA_DEBUGGING
  cerr << "(Calling evm2wasm.js with command: " << cmd << ")" << endl;
#endif

  int ret = system(cmd.data());
  unlink(fileEVM.data());

  if (ret != 0) {
#if HERA_DEBUGGING
    cerr << "evm2wasm.js failed" << endl;
#endif

    unlink(fileWASM.data());
    return vector<uint8_t>();
  }

  ifstream is(fileWASM);
  string str((istreambuf_iterator<char>(is)),
                 istreambuf_iterator<char>());

  unlink(fileWASM.data());

#if HERA_DEBUGGING
  cerr << "evm2wasm.js done (output " << str.length() << " bytes)" << endl;
#endif

  return vector<uint8_t>(str.begin(), str.end());
}

// Calls evm2wasm (through the built-in C++ interface) with input data @input.
// @returns the compiled output or empty output otherwise.
vector<uint8_t> evm2wasm_cpp(vector<uint8_t> const& input, bool evmTrace) {
#if HERA_DEBUGGING
  cerr << "Calling evm2wasm.cpp (input " << input.size() << " bytes)..." << endl;
#endif

  string str = evm2wasm::evm2wasm(input, evmTrace);

#if HERA_DEBUGGING
  cerr << "evm2wasm.cpp done (output " << str.length() << " bytes)" << endl;
#endif

  return vector<uint8_t>(str.begin(), str.end());
}

// Calls the evm2wasm contract with input data @input.
// @returns the compiled output or empty output otherwise.
vector<uint8_t> evm2wasm(evmc_context* context, vector<uint8_t> const& input) {
#if HERA_DEBUGGING
  cerr << "Calling evm2wasm (input " << input.size() << " bytes)..." << endl;
#endif

  int64_t startgas = numeric_limits<int64_t>::max(); // do not charge for metering yet (give unlimited gas)
  int64_t gas = startgas;
  vector<uint8_t> ret = callSystemContract(
    context,
    evm2wasmAddress,
    gas,
    input
  );

#if HERA_DEBUGGING
  cerr << "evm2wasm done (output " << ret.size() << " bytes, used " << (startgas - gas) << " gas)" << endl;
#endif

  return ret;
}

// NOTE: This should be caught during deployment time by the Sentinel.
void validate_contract(Module & module)
{
  ensureCondition(
    module.getExportOrNull(Name("main")) != nullptr,
    ContractValidationFailure,
    "Contract entry point (\"main\") missing."
  );

  ensureCondition(
    module.getExportOrNull(Name("memory")) != nullptr,
    ContractValidationFailure,
    "Contract export (\"memory\") missing."
  );

  ensureCondition(
    module.exports.size() == 2,
    ContractValidationFailure,
    "Contract exports more than (\"main\") and (\"memory\")."
  );

  for (auto const& import: module.imports) {
    ensureCondition(
      import->module == Name("ethereum")
#if HERA_DEBUGGING
      || import->module == Name("debug")
#endif
      ,
      ContractValidationFailure,
      "Import from invalid namespace."
    );
  }
}

// Execute the contract through Binaryen.
ExecutionResult execute(
  evmc_context* context,
  vector<uint8_t> const& code,
  vector<uint8_t> const& state_code,
  evmc_message const& msg,
  bool meterInterfaceGas
) {
#if HERA_DEBUGGING
  cerr << "Executing..." << endl;
#endif

  Module module;

  // Load module
  try {
    WasmBinaryBuilder parser(module, reinterpret_cast<vector<char> const&>(code), false);
    parser.read();
  } catch (ParseException const& e) {
    string msg = "Error in parsing WASM binary: '" + e.text + "'";
    if (e.line != size_t(-1))
      msg += " (at " + to_string(e.line) + ":" + to_string(e.col) + ")";
    ensureCondition(false, ContractValidationFailure, msg);
  }

  // Print
  // WasmPrinter::printModule(module);

  // Validate
  ensureCondition(
    WasmValidator().validate(module),
    ContractValidationFailure,
    "Module is not valid."
  );

  // NOTE: This should be caught during deployment time by the Sentinel.
  validate_contract(module);

  // NOTE: DO NOT use the optimiser here, it will conflict with metering

  // Interpret
  ExecutionResult result;
  EthereumInterface interface(context, state_code, msg, result, meterInterfaceGas);
  ModuleInstance instance(module, &interface);

  try {
    Name main = Name("main");
    LiteralList args;
    instance.callExport(main, args);
  } catch (EndExecution const&) {
    // This exception is ignored here because we consider it to be a success.
    // It is only a clutch for POSIX style exit()
  }

  return result;
}

void hera_destroy_result(evmc_result const* result) noexcept
{
  delete[] result->output_data;
}

evmc_result hera_execute(
  evmc_instance *instance,
  evmc_context *context,
  enum evmc_revision rev,
  const evmc_message *msg,
  const uint8_t *code,
  size_t code_size
) noexcept {
  evmc_result ret;
  memset(&ret, 0, sizeof(evmc_result));
  
  hera_instance* hera = static_cast<hera_instance*>(instance);
  try {
    heraAssert(rev == EVMC_BYZANTIUM, "Only Byzantium supported.");
    heraAssert(msg->gas >= 0, "EVMC supplied negative startgas");

    bool meterInterfaceGas = true;

    // the bytecode residing in the state - this will be used by interface methods (i.e. codecopy)
    vector<uint8_t> state_code(code, code + code_size);

    // the actual executable code - this can be modified (metered or evm2wasm compiled)
    vector<uint8_t> run_code(code, code + code_size);

    // ensure we can only handle WebAssembly version 1
    if (!hasWasmPreamble(run_code)) {
      switch (hera->evm_mode) {
      case hera_evm_mode::evm2wasm_contract:
        run_code = evm2wasm(context, run_code);
        ensureCondition(run_code.size() > 5, ContractValidationFailure, "Transcompiling via evm2wasm failed");
        // TODO: enable this once evm2wasm does metering of interfaces
        // meterInterfaceGas = false;
        break;
      case hera_evm_mode::evm2wasm_cpp:
      case hera_evm_mode::evm2wasm_cpp_tracing:
        run_code = evm2wasm_cpp(run_code, hera->evm_mode == hera_evm_mode::evm2wasm_cpp_tracing);
        ensureCondition(run_code.size() > 5, ContractValidationFailure, "Transcompiling via evm2wasm.cpp failed");
        // TODO: enable this once evm2wasm does metering of interfaces
        // meterInterfaceGas = false;
        break;
      case hera_evm_mode::evm2wasm_js:
      case hera_evm_mode::evm2wasm_js_tracing:
        run_code = evm2wasm_js(run_code, hera->evm_mode == hera_evm_mode::evm2wasm_js_tracing);
        ensureCondition(run_code.size() > 5, ContractValidationFailure, "Transcompiling via evm2wasm.js failed");
        // TODO: enable this once evm2wasm does metering of interfaces
        // meterInterfaceGas = false;
        break;
      case hera_evm_mode::fallback:
        ret.status_code = EVMC_REJECTED;
        return ret;
      case hera_evm_mode::reject:
        ret.status_code = EVMC_FAILURE;
        return ret;
      default:
        heraAssert(false, "");
      }
    } else if (msg->kind == EVMC_CREATE) {
      // Meter the deployment (constructor) code if it is WebAssembly
      if (hera->metering)
        run_code = sentinel(context, run_code);
      ensureCondition(run_code.size() > 5, ContractValidationFailure, "Invalid contract or metering failed.");
    }

    heraAssert(hera->wasm_engine == hera_wasm_engine::binaryen, "Unsupported wasm engine.");
    
#if HERA_DEBUGGING
    debugPrintPreloadList(hera);
#endif
    if (resolveSystemContract(hera, &msg->destination)) {
#if HERA_DEBUGGING
      cerr << "Overriding code" << endl;
      cerr << "Original code: " << bytesAsHexStr(run_code.data(), run_code.size()) << endl;
#endif
      run_code = overrideRunCode(&msg->destination, hera);
      run_code.shrink_to_fit();
#if HERA_DEBUGGING
      cerr << "New code: " << bytesAsHexStr(run_code.data(), run_code.size()) << endl;
#endif
    }

    ExecutionResult result = execute(context, run_code, state_code, *msg, meterInterfaceGas);
    heraAssert(result.gasLeft >= 0, "Negative gas left after execution.");

    // copy call result
    if (result.returnValue.size() > 0) {
      vector<uint8_t> returnValue;

      if (msg->kind == EVMC_CREATE && !result.isRevert && hasWasmPreamble(result.returnValue)) {
        // Meter the deployed code if it is WebAssembly
        returnValue = hera->metering ? sentinel(context, result.returnValue) : move(result.returnValue);
        ensureCondition(returnValue.size() > 5, ContractValidationFailure, "Invalid contract or metering failed.");
      } else {
        returnValue = move(result.returnValue);
      }

      uint8_t* output_data = new uint8_t[returnValue.size()];
      copy(returnValue.begin(), returnValue.end(), output_data);

      ret.output_size = returnValue.size();
      ret.output_data = output_data;
      ret.release = hera_destroy_result;
    }

    ret.status_code = result.isRevert ? EVMC_REVERT : EVMC_SUCCESS;
    ret.gas_left = result.gasLeft;
  } catch (EndExecution const&) {
    ret.status_code = EVMC_INTERNAL_ERROR;
#if HERA_DEBUGGING
    cerr << "EndExecution exception has leaked through." << endl;
#endif
  } catch (VMTrap const& e) {
    // TODO: use specific error code? EVMC_INVALID_INSTRUCTION or EVMC_TRAP_INSTRUCTION?
    ret.status_code = EVMC_FAILURE;
#if HERA_DEBUGGING
    cerr << e.what() << endl;
#endif
  } catch (ArgumentOutOfRange const& e) {
    // TODO: use specific error code? EVMC_ARGUMENT_OUT_OF_RANGE?
    ret.status_code = EVMC_FAILURE;
#if HERA_DEBUGGING
    cerr << e.what() << endl;
#endif
  } catch (OutOfGas const& e) {
    ret.status_code = EVMC_OUT_OF_GAS;
#if HERA_DEBUGGING
    cerr << e.what() << endl;
#endif
  } catch (ContractValidationFailure const& e) {
    ret.status_code = EVMC_CONTRACT_VALIDATION_FAILURE;
#if HERA_DEBUGGING
    cerr << e.what() << endl;
#endif
  } catch (InvalidMemoryAccess const& e) {
    ret.status_code = EVMC_INVALID_MEMORY_ACCESS;
#if HERA_DEBUGGING
    cerr << e.what() << endl;
#endif
  } catch (StaticModeViolation const& e) {
    ret.status_code = EVMC_STATIC_MODE_VIOLATION;
#if HERA_DEBUGGING
    cerr << e.what() << endl;
#endif
  } catch (InternalErrorException const& e) {
    ret.status_code = EVMC_INTERNAL_ERROR;
#if HERA_DEBUGGING
    cerr << "InternalError: " << e.what() << endl;
#endif
  } catch (exception const& e) {
    ret.status_code = EVMC_INTERNAL_ERROR;
#if HERA_DEBUGGING
    cerr << "Unknown exception: " << e.what() << endl;
#endif
  } catch (...) {
    ret.status_code = EVMC_INTERNAL_ERROR;
#if HERA_DEBUGGING
    cerr << "Totally unknown exception" << endl;
#endif
  }

  return ret;
}

// we aren't at c++17 yet so a pair will be used rather than std::optional
pair<evmc_address, bool> resolve_alias_to_address(string const& alias) {
  map<string, evmc_address> alias_to_addr_map = {
    { string("sentinel"), sentinelAddress },
    { string("evm2wasm"), evm2wasmAddress }
  };

  evmc_address ret = {};
  bool status = false;
  
  if (alias_to_addr_map.count(alias) != 0) {
#if HERA_DEBUGGING
    cerr << "Successfully resolved alias " << alias 
      << " to address " << hex << alias_to_addr_map[alias].bytes 
      << dec << endl;
#endif
    ret = alias_to_addr_map[alias];
    status = true;
  }

  return pair<evmc_address, bool>(ret, status);
}

pair<evmc_address, bool> parse_hex_addr(string const& addr) {
  evmc_address ret = {};
  
#if HERA_DEBUGGING
  cerr << "Trying to parse address field" << endl;
#endif

  if (addr.find("0x") != 0) { 
    cerr << addr << ": "; 
    heraAssert(false, "Address missing '0x' prefix!");
  }

  heraAssert(addr.size() <= 42, "Address specified is too long!");

  string addr_raw;
  //if the number of nibbles is odd, we must prepend a zero for unmarshalling to work correctly.
  if (addr.size() % 2 > 0) addr_raw.push_back('0');
  addr_raw.append(addr.substr(2, string::npos));

  size_t hex_length = addr_raw.size();

#if HERA_DEBUGGING
  cerr << "Got hex string of length " << hex_length << ": " << addr_raw << endl;
#endif 

  //Use strtol to parse hex string into binary
  for (size_t i = hex_length / 2, j = 20; i > 0 && j > 0; i--, j--) {
    string byte_str = addr_raw.substr(((i - 1) * 2), 2);

    uint8_t byte = uint8_t(strtol(byte_str.c_str(), nullptr, 16));

    ret.bytes[j - 1] = byte;
  }

#if HERA_DEBUGGING
  cerr << "Successfully unmarshalled hex string into address struct" << endl;
#endif

  return pair<evmc_address, bool>(ret, true);
}

pair<evmc_address, bool> parse_preload_addr(const char *name)
{
  assert(name != nullptr);

  pair<evmc_address, bool> ret = { {}, false };
  string evmc_option_raw = string(name);

#if HERA_DEBUGGING
  cerr << "Trying to parse EVMC option as preload flag: " << evmc_option_raw << endl;
#endif 

  //Check the "sys:" syntax by comparing substring
  if (evmc_option_raw.find("sys:") != 0) {
#if HERA_DEBUGGING
  cerr << "Unsuccessfully parsed preload command, prefix malformed: " << evmc_option_raw.substr(0, 4) << endl;
#endif
    return ret;
  }
  
  //Parse the address field from the option name and try to determine an address
  string opt_address_to_load = evmc_option_raw.substr(4, string::npos);

  //Try to resolve the substring to an alias first
#if HERA_DEBUGGING
  cerr << "Attempting to parse option as an alias: " << opt_address_to_load << endl;
#endif
  ret = resolve_alias_to_address(opt_address_to_load);
  
  //If alias resolver returns false, try parsing to a hex address
  if (ret.second == false) {
#if HERA_DEBUGGING
    cerr << "Unsuccessfully resolved option to an alias, trying to unmarshal from a hex string" << endl;
#endif
    ret = parse_hex_addr(opt_address_to_load);
  }

  return ret;
}

int hera_set_option(
  evmc_instance *instance,
  char const *name,
  char const *value
) noexcept {
  hera_instance* hera = static_cast<hera_instance*>(instance);
  if (strcmp(name, "fallback") == 0) {
    if (strcmp(value, "true") == 0)
      hera->evm_mode = hera_evm_mode::fallback;
    return 1;
  }

  if (strcmp(name, "evm2wasm") == 0) {
    if (strcmp(value, "true") == 0)
      hera->evm_mode = hera_evm_mode::evm2wasm_contract;
    return 1;
  }

  if (strcmp(name, "evm2wasm.cpp") == 0) {
    if (strcmp(value, "true") == 0)
      hera->evm_mode = hera_evm_mode::evm2wasm_cpp;
    return 1;
  }

  if (strcmp(name, "evm2wasm.cpp-trace") == 0) {
    if (strcmp(value, "true") == 0)
      hera->evm_mode = hera_evm_mode::evm2wasm_cpp_tracing;
    return 1;
  }

  if (strcmp(name, "evm2wasm.js") == 0) {
    if (strcmp(value, "true") == 0)
      hera->evm_mode = hera_evm_mode::evm2wasm_js;
    return 1;
  }

  if (strcmp(name, "evm2wasm.js-trace") == 0) {
    if (strcmp(value, "true") == 0)
      hera->evm_mode = hera_evm_mode::evm2wasm_js_tracing;
    return 1;
  }

  if (strcmp(name, "metering") == 0) {
    hera->metering = strcmp(value, "true") == 0;
    return 1;
  }

  if (strcmp(name, "engine") == 0) {
     if (strcmp(value, "binaryen") == 0)
       hera->wasm_engine = hera_wasm_engine::binaryen;
#if HAVE_WABT
     if (strcmp(value, "wabt") == 0)
       hera->wasm_engine = hera_wasm_engine::wabt;
#endif
#if HAVE_WAVM
     if (strcmp(value, "wavm") == 0)
       hera->wasm_engine = hera_wasm_engine::wavm;
#endif
     return 1;
  }

  auto preload_addr = parse_preload_addr(name);
  if (preload_addr.second == true) {
    hera->contract_preload_list.push_back(pair<evmc_address, string>(preload_addr.first, string(value)));
    return 1;
  }

  return 0;
}

void hera_destroy(evmc_instance* instance) noexcept
{
  hera_instance* hera = static_cast<hera_instance*>(instance);
  delete hera;
}

} // anonymous namespace

extern "C" {

evmc_instance* evmc_create_hera() noexcept
{
  hera_instance* instance = new hera_instance;
  instance->destroy = hera_destroy;
  instance->execute = hera_execute;
  instance->set_option = hera_set_option;
  return instance;
}

}
