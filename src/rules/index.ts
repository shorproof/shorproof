/**
 * Rule registry. Rule groups live in sibling files and are aggregated here so
 * the engine has a single import surface. Contributors add rules to a group
 * file (or a new one) without touching detection code.
 */
export { DEP_RULES } from './deps-packages.ts';
