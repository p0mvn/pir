/* tslint:disable */
/* eslint-disable */

export class PirClient {
  free(): void;
  [Symbol.dispose](): void;
  /**
   * Get the number of records in the database
   */
  num_records(): number;
  /**
   * Get the record size in bytes
   */
  record_size(): number;
  /**
   * Hash a password to SHA-1 (uppercase hex)
   */
  static hash_password(password: string): string;
  /**
   * XOR three records to decode the final value
   */
  decode_keyword(rec0: Uint8Array, rec1: Uint8Array, rec2: Uint8Array): Uint8Array;
  /**
   * Debug: Get the first few elements of A_col matrix
   */
  get_a_col_data(): Uint32Array;
  /**
   * Debug: Get the first few elements of A_row matrix
   */
  get_a_row_data(): Uint32Array;
  /**
   * Get the 3 record indices for a keyword (hash) query
   */
  get_keyword_indices(keyword: string): Uint32Array;
  /**
   * Get the 3 record indices for a password (hashes it first)
   */
  get_password_indices(password: string): Uint32Array;
  /**
   * Create a new PIR client from setup data (JSON)
   */
  constructor(setup_json: string, lwe_params_json: string, filter_params_json: string);
  /**
   * Generate a PIR query for a specific record index
   * Returns JSON: { state: JsQueryState, query: JsDoublePirQuery }
   */
  query(record_idx: number): string;
  /**
   * Recover a record from the server's answer
   * Takes: state_json (JsQueryState), answer_json (JsDoublePirAnswer)
   * Returns: the recovered bytes as a Uint8Array
   */
  recover(state_json: string, answer_json: string): Uint8Array;
}

export function init(): void;

/**
 * Get version info
 */
export function version(): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_pirclient_free: (a: number, b: number) => void;
  readonly pirclient_decode_keyword: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
  readonly pirclient_get_a_col_data: (a: number) => [number, number];
  readonly pirclient_get_a_row_data: (a: number) => [number, number];
  readonly pirclient_get_keyword_indices: (a: number, b: number, c: number) => [number, number];
  readonly pirclient_get_password_indices: (a: number, b: number, c: number) => [number, number];
  readonly pirclient_hash_password: (a: number, b: number) => [number, number];
  readonly pirclient_new: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  readonly pirclient_num_records: (a: number) => number;
  readonly pirclient_query: (a: number, b: number) => [number, number, number, number];
  readonly pirclient_record_size: (a: number) => number;
  readonly pirclient_recover: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly version: () => [number, number];
  readonly init: () => void;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
