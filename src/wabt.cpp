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
#include "eei.h"
#include "exceptions.h"

using namespace std;

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

  // This is the wasm state
  wabt::interp::Environment env;

  // Lets instantiate our state
  ExecutionResult result;
  WabtEthereumInterface interface(context, state_code, msg, result, meterInterfaceGas);

  // Lets add our host module
  wabt::interp::HostModule* host_module = env.AppendHostModule("ethereum");
  host_module->import_delegate.reset(&interface);

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
  heraAssert(module, "module not loaded?!");

  // FIXME: iterate and find
  heraAssert(module->exports.size() > 0, "not exports");
  wabt::interp::Export & mainFunction = module->exports[0];
  heraAssert(mainFunction.name == "main", "main not found");

  // No tracing, not threads
  wabt::interp::Executor executor(&env, nullptr, wabt::interp::Thread::Options{});
  
  // Execute main
  wabt::interp::ExecResult wabtResult = executor.RunExport(&mainFunction, wabt::interp::TypedValues{});

  // FIXME populate output

  return ExecutionResult{};
}

}

#endif
