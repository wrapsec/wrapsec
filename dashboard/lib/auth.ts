export async function login(apiKey: string): Promise<boolean> {
  const response = await fetch("/api/auth/login", {
    method:  "POST",
    headers: { "Content-Type": "application/json" },
    body:    JSON.stringify({ apiKey }),
  })
  return response.ok
}

export async function logout(): Promise<void> {
  await fetch("/api/auth/logout", { method: "POST" })
}