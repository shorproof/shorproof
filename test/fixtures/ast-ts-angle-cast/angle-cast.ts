// Regression guard (discovered miss class): a legacy TypeScript angle-bracket
// cast in a .ts file. With the jsx plugin enabled, `<number>input` fails to
// parse and EVERY finding in the file is lost — including the vulnerable call
// below. Extension-aware plugin selection (.ts -> no jsx) fixes it.
import { generateKeyPairSync } from 'node:crypto';

export function makeKey(input: unknown) {
  const modulusLength = (<number>input) || 2048;
  return generateKeyPairSync('rsa', { modulusLength });
}
