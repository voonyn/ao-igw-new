import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";
import jsxA11y from "eslint-plugin-jsx-a11y";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // The accessibility gate (console-accessibility). Before it, `pnpm lint`
  // reported none of the defects this change fixed: a click handler on a
  // non-interactive element, a label associated with nothing, a control with no
  // accessible name.
  //
  // It covers what STATIC ANALYSIS can see, and nothing more. Focus ORDER,
  // contrast against actually-rendered backgrounds, and screen-reader flow are
  // hand-verified — a green run here is not evidence that any of those were
  // done, and must not be presented as a conformance claim.
  //
  // Violations get fixed, not disabled. A rule that has to be switched off to
  // land is a rule that should not have been switched on.
  //
  // Rules only, not the whole flat config: `eslint-config-next/core-web-vitals`
  // already registers the `jsx-a11y` plugin (with a much smaller rule subset),
  // and registering it twice is a hard config error.
  { rules: jsxA11y.flatConfigs.recommended.rules },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
  ]),
]);

export default eslintConfig;
