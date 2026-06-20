export type ToolErrorCode =
  | 'invalid_input'
  | 'not_found'
  | 'upstream_error'
  | 'timeout'
  | 'unsupported';

const STATUS: Record<ToolErrorCode, number> = {
  invalid_input: 400,
  not_found: 404,
  upstream_error: 502,
  timeout: 504,
  unsupported: 501,
};

/**
 * A typed, transport-agnostic error. The API layer maps `.status` to an HTTP code
 * and `.code` to a stable machine-readable string.
 */
export class ToolError extends Error {
  readonly code: ToolErrorCode;
  readonly status: number;

  constructor(code: ToolErrorCode, message: string, status?: number) {
    super(message);
    this.name = 'ToolError';
    this.code = code;
    this.status = status ?? STATUS[code];
  }

  toJSON() {
    return { error: { code: this.code, message: this.message } };
  }
}

export function isToolError(err: unknown): err is ToolError {
  return err instanceof ToolError;
}
