/**
 * Minimal page-side DOM ambient for Playwright evaluate probes. The project
 * compiles without the DOM lib, so this declares only the surface the
 * in-page probes touch that is not already ambient. Elements are
 * intentionally `any`: the probes run inside Chrome.
 */
declare global {
  const document: {
    querySelectorAll(selector: string): any[]
    body: { innerText: string } | null
  }
}

export {}
