// Binding style 2/6: renamed named import.
// The local name `makeKeys` bears no resemblance to the export name, so a
// name-based scanner misses this. We key off the binding's imported name.
import { generateKeyPairSync as makeKeys } from 'node:crypto';

export function makeRsaKeypair() {
  return makeKeys('rsa', { modulusLength: 2048 });
}
