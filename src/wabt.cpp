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

#if HERA_WABT

#include <vector>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>
#include <string.h>
#include <fstream>
#include <iostream>

#include "src/binary-reader-interp.h"
#include "src/binary-reader.h"
#include "src/cast.h"
#include "src/error-handler.h"
#include "src/feature.h"
#include "src/interp.h"
#include "src/literal.h"
#include "src/option-parser.h"
#include "src/resolve-names.h"
#include "src/stream.h"
#include "src/validator.h"
#include "src/wast-lexer.h"
#include "src/wast-parser.h"

#include "wabt.h"
#include "debugging.h"
#include "eei.h"
#include "exceptions.h"

using namespace std;
using namespace wabt;

namespace hera {

wabt::Result WabtEthereumInterface::ImportFunc(
  wabt::interp::FuncImport* import,
  wabt::interp::Func* func,
  wabt::interp::FuncSignature* func_sig,
  const ErrorCallback& callback
) {
  (void)import;
  (void)func;
  (void)func_sig;
  (void)callback;
  wabt::interp::HostFunc *hostFunc = reinterpret_cast<wabt::interp::HostFunc*>(func);
  cout << "Importing " << import->field_name << endl;
  if (import->field_name == "useGas") {
    hostFunc->callback = wabtUseGas;
    hostFunc->user_data = this;
    return wabt::Result::Ok;
  } else if (import->field_name == "finish") {
    hostFunc->callback = wabtFinish;
    hostFunc->user_data = this;
    return wabt::Result::Ok;
  }
  return wabt::Result::Error;
}

wabt::Result WabtEthereumInterface::ImportMemory(
  wabt::interp::MemoryImport* import,
  wabt::interp::Memory* mem,
  const ErrorCallback& callback
) {
  (void)import;
  (void)mem;
  (void)callback;
  return wabt::Result::Error;
}

wabt::Result WabtEthereumInterface::ImportGlobal(
  wabt::interp::GlobalImport* import,
  wabt::interp::Global* global,
  const ErrorCallback& callback
) {
  (void)import;
  (void)global;
  (void)callback;
  return wabt::Result::Error;
}

wabt::Result WabtEthereumInterface::ImportTable(
  wabt::interp::TableImport* import,
  wabt::interp::Table* table,
  const ErrorCallback& callback
) {
  (void)import;
  (void)table;
  (void)callback;
  return wabt::Result::Error;
}

interp::Result WabtEthereumInterface::wabtUseGas(
  const interp::HostFunc* func,
  const interp::FuncSignature* sig,
  Index num_args,
  interp::TypedValue* args,
  Index num_results,
  interp::TypedValue* out_results,
  void* user_data
) {
  (void)func;
  (void)sig;
  (void)num_results;
  (void)out_results;

  heraAssert(num_args == 1, "Invalid number of args");

  WabtEthereumInterface *interface = reinterpret_cast<WabtEthereumInterface*>(user_data);

  int64_t gas = static_cast<int64_t>(args[0].value.i64);

  // FIXME: handle host trap here
  interface->eeiUseGas(gas);

  return interp::Result::Ok;
}

interp::Result WabtEthereumInterface::wabtFinish(
  const interp::HostFunc* func,
  const interp::FuncSignature* sig,
  Index num_args,
  interp::TypedValue* args,
  Index num_results,
  interp::TypedValue* out_results,
  void* user_data
) {
  (void)func;
  (void)sig;
  (void)num_results;
  (void)out_results;

  heraAssert(num_args == 2, "Invalid number of args");

  WabtEthereumInterface *interface = reinterpret_cast<WabtEthereumInterface*>(user_data);

  uint32_t offset = args[0].value.i32;
  uint32_t length = args[1].value.i32;

  // FIXME: handle host trap here
  interface->eeiRevertOrFinish(false, offset, length);

  return interp::Result::Ok;
}

ExecutionResult WabtEngine::execute(
  evmc_context* context,
  vector<uint8_t> const& code,
  vector<uint8_t> const& state_code,
  evmc_message const& msg,
  bool meterInterfaceGas
) {
  (void)context;
  (void)code;
  (void)state_code;
  (void)msg;
  (void)meterInterfaceGas;

  HERA_DEBUG << "Executing..." << endl;

  // This is the wasm state
  wabt::interp::Environment env;

  // Lets instantiate our state
  ExecutionResult result;
  // FIXME: this only uses memory index 0 ...
  WabtEthereumInterface* interface = new WabtEthereumInterface(context, state_code, msg, result, meterInterfaceGas, env.GetMemory(0));

  // Lets add our host module
  wabt::interp::HostModule* hostModule = env.AppendHostModule("ethereum");
  heraAssert(hostModule, "Failed to create host module.");
  hostModule->import_delegate.reset(interface);

  std::unique_ptr<wabt::FileStream> errorStream = wabt::FileStream::CreateStderr();

  wabt::ReadBinaryOptions options(
    wabt::Features{},
    errorStream.get(),
    true, // ReadDebugNames
    true, // StopOnFirstError
    true // FailOnCustomSectionError
  );

  wabt::ErrorHandlerFile error_handler(wabt::Location::Type::Binary);
  wabt::interp::DefinedModule* module = nullptr;
  wabt::ReadBinaryInterp(
    &env,
    code.data(),
    code.size(),
    &options,
    &error_handler,
    &module
  );
  ensureCondition(module, ContractValidationFailure, "Module failed to load.");

  // FIXME: iterate and find
  heraAssert(module->exports.size() > 1, "not exports");
  wabt::interp::Export & mainFunction = module->exports[1];
  heraAssert(mainFunction.name == "main", "main not found");

  // No tracing, not threads
  wabt::interp::Executor executor(&env, nullptr, wabt::interp::Thread::Options{});

  // FIXME: really bad design
  interface->setWasmMemory(env.GetMemory(0));

  // Execute main
  try {
    wabt::interp::ExecResult wabtResult = executor.RunExport(&mainFunction, wabt::interp::TypedValues{});
  } catch (EndExecution const&) {
    // This exception is ignored here because we consider it to be a success.
    // It is only a clutch for POSIX style exit()
  }

  // FIXME populate output

  return ExecutionResult{};
}

}

#endif
