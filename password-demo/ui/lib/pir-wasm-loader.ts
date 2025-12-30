// WASM loader for PIR client
// This handles loading the WASM module in Next.js

let wasmModule: WebAssembly.Module | null = null;
let wasmInstance: WebAssembly.Instance | null = null;
let wasm: WasmExports | null = null;

// Types for the WASM exports
interface WasmExports {
  memory: WebAssembly.Memory;
  __wbg_pirclient_free: (a: number, b: number) => void;
  pirclient_decode_keyword: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
  pirclient_get_keyword_indices: (a: number, b: number, c: number) => [number, number];
  pirclient_new: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  pirclient_num_records: (a: number) => number;
  pirclient_query: (a: number, b: number) => [number, number, number, number];
  pirclient_record_size: (a: number) => number;
  pirclient_recover: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  version: () => [number, number];
  init: () => void;
  __wbindgen_free: (a: number, b: number, c: number) => void;
  __wbindgen_exn_store: (a: number) => void;
  __externref_table_alloc: () => number;
  __wbindgen_externrefs: WebAssembly.Table;
  __wbindgen_malloc: (a: number, b: number) => number;
  __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  __externref_table_dealloc: (a: number) => void;
  __wbindgen_start: () => void;
}

// Text encoder/decoder
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });

// Memory views
let cachedUint8ArrayMemory: Uint8Array | null = null;
let cachedUint32ArrayMemory: Uint32Array | null = null;
let cachedDataViewMemory: DataView | null = null;

function getUint8ArrayMemory(): Uint8Array {
  if (cachedUint8ArrayMemory === null || cachedUint8ArrayMemory.byteLength === 0) {
    cachedUint8ArrayMemory = new Uint8Array(wasm!.memory.buffer);
  }
  return cachedUint8ArrayMemory;
}

function getUint32ArrayMemory(): Uint32Array {
  if (cachedUint32ArrayMemory === null || cachedUint32ArrayMemory.byteLength === 0) {
    cachedUint32ArrayMemory = new Uint32Array(wasm!.memory.buffer);
  }
  return cachedUint32ArrayMemory;
}

function getDataViewMemory(): DataView {
  if (cachedDataViewMemory === null || cachedDataViewMemory.buffer !== wasm!.memory.buffer) {
    cachedDataViewMemory = new DataView(wasm!.memory.buffer);
  }
  return cachedDataViewMemory;
}

// String handling
let WASM_VECTOR_LEN = 0;

function passStringToWasm(arg: string): [number, number] {
  const buf = textEncoder.encode(arg);
  const ptr = wasm!.__wbindgen_malloc(buf.length, 1) >>> 0;
  getUint8ArrayMemory().subarray(ptr, ptr + buf.length).set(buf);
  WASM_VECTOR_LEN = buf.length;
  return [ptr, WASM_VECTOR_LEN];
}

function getStringFromWasm(ptr: number, len: number): string {
  ptr = ptr >>> 0;
  return textDecoder.decode(getUint8ArrayMemory().subarray(ptr, ptr + len));
}

function passArray8ToWasm(arg: Uint8Array): [number, number] {
  const ptr = wasm!.__wbindgen_malloc(arg.length, 1) >>> 0;
  getUint8ArrayMemory().set(arg, ptr);
  WASM_VECTOR_LEN = arg.length;
  return [ptr, WASM_VECTOR_LEN];
}

function getArrayU8FromWasm(ptr: number, len: number): Uint8Array {
  ptr = ptr >>> 0;
  return getUint8ArrayMemory().subarray(ptr, ptr + len).slice();
}

function getArrayU32FromWasm(ptr: number, len: number): Uint32Array {
  ptr = ptr >>> 0;
  return getUint32ArrayMemory().subarray(ptr / 4, ptr / 4 + len).slice();
}

// Externref table handling
function addToExternrefTable(obj: unknown): number {
  const idx = wasm!.__externref_table_alloc();
  wasm!.__wbindgen_externrefs.set(idx, obj);
  return idx;
}

function takeFromExternrefTable(idx: number): unknown {
  const value = wasm!.__wbindgen_externrefs.get(idx);
  wasm!.__externref_table_dealloc(idx);
  return value;
}

function handleError(f: Function, args: IArguments): unknown {
  try {
    return f.apply(null, args);
  } catch (e) {
    const idx = addToExternrefTable(e);
    wasm!.__wbindgen_exn_store(idx);
  }
}

// PIR Client class
const PirClientFinalization = typeof FinalizationRegistry === 'undefined'
  ? { register: () => {}, unregister: () => {} }
  : new FinalizationRegistry((ptr: number) => wasm!.__wbg_pirclient_free(ptr >>> 0, 1));

export class PirClient {
  private __wbg_ptr: number = 0;

  constructor(setup_json: string, lwe_params_json: string, filter_params_json: string) {
    const [ptr0, len0] = passStringToWasm(setup_json);
    const [ptr1, len1] = passStringToWasm(lwe_params_json);
    const [ptr2, len2] = passStringToWasm(filter_params_json);
    const ret = wasm!.pirclient_new(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[2]) {
      throw takeFromExternrefTable(ret[1]);
    }
    this.__wbg_ptr = ret[0] >>> 0;
    PirClientFinalization.register(this, this.__wbg_ptr, this);
  }

  free(): void {
    const ptr = this.__wbg_ptr;
    this.__wbg_ptr = 0;
    PirClientFinalization.unregister(this);
    wasm!.__wbg_pirclient_free(ptr, 0);
  }

  num_records(): number {
    return wasm!.pirclient_num_records(this.__wbg_ptr) >>> 0;
  }

  record_size(): number {
    return wasm!.pirclient_record_size(this.__wbg_ptr) >>> 0;
  }

  get_keyword_indices(keyword: string): Uint32Array {
    const [ptr0, len0] = passStringToWasm(keyword);
    const ret = wasm!.pirclient_get_keyword_indices(this.__wbg_ptr, ptr0, len0);
    const result = getArrayU32FromWasm(ret[0], ret[1]);
    wasm!.__wbindgen_free(ret[0], ret[1] * 4, 4);
    return result;
  }

  query(record_idx: number): string {
    const ret = wasm!.pirclient_query(this.__wbg_ptr, record_idx);
    if (ret[3]) {
      throw takeFromExternrefTable(ret[2]);
    }
    const result = getStringFromWasm(ret[0], ret[1]);
    wasm!.__wbindgen_free(ret[0], ret[1], 1);
    return result;
  }

  recover(state_json: string, answer_json: string): Uint8Array {
    const [ptr0, len0] = passStringToWasm(state_json);
    const [ptr1, len1] = passStringToWasm(answer_json);
    const ret = wasm!.pirclient_recover(this.__wbg_ptr, ptr0, len0, ptr1, len1);
    if (ret[3]) {
      throw takeFromExternrefTable(ret[2]);
    }
    const result = getArrayU8FromWasm(ret[0], ret[1]);
    wasm!.__wbindgen_free(ret[0], ret[1], 1);
    return result;
  }

  decode_keyword(rec0: Uint8Array, rec1: Uint8Array, rec2: Uint8Array): Uint8Array {
    const [ptr0, len0] = passArray8ToWasm(rec0);
    const [ptr1, len1] = passArray8ToWasm(rec1);
    const [ptr2, len2] = passArray8ToWasm(rec2);
    const ret = wasm!.pirclient_decode_keyword(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
    const result = getArrayU8FromWasm(ret[0], ret[1]);
    wasm!.__wbindgen_free(ret[0], ret[1], 1);
    return result;
  }
}

export function version(): string {
  const ret = wasm!.version();
  const result = getStringFromWasm(ret[0], ret[1]);
  wasm!.__wbindgen_free(ret[0], ret[1], 1);
  return result;
}

// Initialize WASM module
export async function initWasm(wasmUrl: string = '/wasm/pir_wasm_bg.wasm'): Promise<void> {
  if (wasm !== null) return;

  const imports: WebAssembly.Imports = {
    wbg: {
      __wbg___wbindgen_throw_dd24417ed36fc46e: function(arg0: number, arg1: number) {
        throw new Error(getStringFromWasm(arg0, arg1));
      },
      __wbg_error_7534b8e9a36f1ab4: function(arg0: number, arg1: number) {
        console.error(getStringFromWasm(arg0, arg1));
        wasm!.__wbindgen_free(arg0, arg1, 1);
      },
      __wbg_getRandomValues_1c61fac11405ffdc: function() {
        return handleError(function(arg0: number, arg1: number) {
          globalThis.crypto.getRandomValues(getUint8ArrayMemory().subarray(arg0, arg0 + arg1));
        }, arguments);
      },
      __wbg_new_8a6f238a6ece86ea: function() {
        return new Error();
      },
      __wbg_stack_0ed75d68575b0f3c: function(arg0: number, arg1: Error) {
        const stack = arg1.stack || '';
        const [ptr, len] = passStringToWasm(stack);
        getDataViewMemory().setInt32(arg0 + 4, len, true);
        getDataViewMemory().setInt32(arg0, ptr, true);
      },
      __wbindgen_cast_2241b6af4c4b2941: function(arg0: number, arg1: number) {
        return getStringFromWasm(arg0, arg1);
      },
      __wbindgen_init_externref_table: function() {
        const table = wasm!.__wbindgen_externrefs;
        const offset = table.grow(4);
        table.set(0, undefined);
        table.set(offset + 0, undefined);
        table.set(offset + 1, null);
        table.set(offset + 2, true);
        table.set(offset + 3, false);
      },
    },
  };

  const response = await fetch(wasmUrl);
  const bytes = await response.arrayBuffer();
  const { instance, module } = await WebAssembly.instantiate(bytes, imports);
  
  wasmModule = module;
  wasmInstance = instance;
  wasm = instance.exports as unknown as WasmExports;
  
  // Reset memory caches
  cachedUint8ArrayMemory = null;
  cachedUint32ArrayMemory = null;
  cachedDataViewMemory = null;
  
  // Initialize
  wasm.__wbindgen_start();
}

export function isInitialized(): boolean {
  return wasm !== null;
}

