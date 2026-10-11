/** Exact ASCII identity names: never trim, decode, or case-fold a binding. */
export function validIdentityUsername(username: string): boolean {
  return username.length >= 1 && username.length <= 128 && !/[^A-Za-z0-9._@+\-]/.test(username);
}
