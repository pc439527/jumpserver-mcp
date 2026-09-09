/** Plain-settable delay; DSH-independent (timer cleanup happens via session close / abort checks). */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

/** Random uppercase-hex marker of len chars, e.g. A8F31C. */
export function randomHex(len: number): string {
  const bytes = new Uint8Array(Math.ceil(len / 2))
  if (typeof globalThis.crypto !== 'undefined' && 'getRandomValues' in globalThis.crypto) {
    globalThis.crypto.getRandomValues(bytes)
  } else {
    for (let i = 0; i < bytes.length; i++) bytes[i] = Math.floor(Math.random() * 256)
  }
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .slice(0, len)
    .toUpperCase()
}
