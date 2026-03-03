import fs from "node:fs";
import path from "node:path";

import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";
import terser from "@rollup/plugin-terser";

const pkgPath = path.resolve(process.cwd(), "package.json");
const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));

const external = [
  ...Object.keys(pkg.dependencies ?? {}),
  ...Object.keys(pkg.peerDependencies ?? {}),
];

const outDir = 'dist';
const cjsDevFileName = 'ecdsa-secp256k1-verification-key-2019.cjs.development.js';
const cjsProdFileName = 'ecdsa-secp256k1-verification-key-2019.cjs.production.min.js';

function generateEntryProxy() {
  return {
    name: "generate-entry-proxy",
    writeBundle() {
      const content = `'use strict'

if (process.env.NODE_ENV === 'production') {
  module.exports = require('./${cjsProdFileName}')
} else {
  module.exports = require('./${cjsDevFileName}')
}
`;

      fs.writeFileSync(`${outDir}/index.js`, content);
    }
  };
}

function injectJsigsImport() {
  return {
    name: "inject-jsigs-import",
    writeBundle() {
      const path = "dist/index.d.ts";

      if (!fs.existsSync(path)) return;

      const content = fs.readFileSync(path, "utf8");

      const header = "import jsigs from 'jsonld-signatures';\n";

      if (!content.startsWith(header)) {
        fs.writeFileSync(path, header + content);
      }
    },
  };
}

export default {
  input: "src/index.ts",
  external,
  plugins: [
    resolve({ extensions: [".mjs", ".js", ".json", ".ts"] }),
    commonjs(),
    typescript({
      tsconfig: "./tsconfig.json",
      compilerOptions: {
        outDir
      },
      sourceMap: true
    }),
    generateEntryProxy(),
    injectJsigsImport()
  ],
  output: [
    {
      file: `${outDir}/${cjsDevFileName}`,
      format: "cjs",
      exports: "named",
      sourcemap: true
    },
    {
      file: `${outDir}/${cjsProdFileName}`,
      format: "cjs",
      exports: "named",
      sourcemap: true,
      plugins: [terser()]
    },
    {
      file: `${outDir}/ecdsa-secp256k1-verification-key-2019.esm.js`,
      format: "es",
      sourcemap: true
    },
  ],
};
