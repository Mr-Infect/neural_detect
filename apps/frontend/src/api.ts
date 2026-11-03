export async function apiFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers || {});
  const token = localStorage.getItem("nd_access_token");
  if (token) headers.set("Authorization", "Bearer " + token);
  return fetch(input, { ...init, headers });
}
