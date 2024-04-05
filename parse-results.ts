#!env node

import * as fs from 'fs';

interface AffectedFunction {
  vulnerable: string;
  fixed: string;
  confirmed: boolean;
}

interface File {
  link: string;
  fixedLink: string;
  affectedFunctions: AffectedFunction[];
}

interface Vulnerability {
  link: string;
  name: string;
  page: string;
  CVE: string;
  CWE: string;
  packageName: string;
  versions: string;
  files: File[];
  errors: any[]; // Replace with a more specific type if possible
  details: string;
  vulnType: string;
}



const data = fs.readFileSync('../results/manuallyConfirmedFullVulnDataset.json', 'utf8');

const vulnerabilities = JSON.parse(data) as Vulnerability[];

const confirmedAffectedFunctions: AffectedFunction[] = [];


vulnerabilities.forEach(vulnerability => {
  vulnerability.files.forEach(file => {
    const confirmedFunctions = file.affectedFunctions.filter(affectedFunction => affectedFunction.confirmed);
    confirmedAffectedFunctions.push(...confirmedFunctions);
  });
});

let uniqueCounter = 0;  // Counter to make names unique

/**
 * Takes a function represented as a string and returns a version of it with a unique name if necessary.
 * @param funcStr The function represented as a string.
 * @returns A string representing the function, modified to have a unique name if it was anonymous.
 */
function ensureUniqueFunctionName(funcStr: string): string {
  if (!funcStr) return funcStr;

  if (!funcStr.endsWith("}")) funcStr = funcStr + ';'
  funcStr = funcStr.replace("[CHECKFS]", "")

  // if (/^(async)?\s*\(?([a-zA-Z_$][0-9a-zA-Z_$]*[,\s]*){0,5}\)?\s*=>\s*{?/.exec(funcStr)) return funcStr;
  if (/^(async)?\s*(\([^)]*\)|[a-zA-Z_$][0-9a-zA-Z_$]*)\s*=>\s*{?/.exec(funcStr)) return funcStr;
  // Check if the function starts with the "function" keyword or is a generator function
  const startsWithFunction = /^(async)?\s*function\s*[^*]/.exec(funcStr)
  const startsWithGenerator = /^(function)?\s*[*]/.exec(funcStr);

  // Check if the function has a name
  const nameMatch = /\s*function(\s*[*])?\s*([a-zA-Z_$][0-9a-zA-Z_$]*)?\s*\(/.exec(funcStr);

  if (startsWithFunction || startsWithGenerator) {
    if (nameMatch?.[2]) {
      // The function already has a name; return it as is
      return funcStr;
    } else {
      // The function is anonymous; generate a unique name
      const uniqueName = `unique_name_${uniqueCounter++}`;
      // Replace the first occurrence of "function" or "*" with the unique name
      if (startsWithFunction) return funcStr.replace("function", `function ${uniqueName}`)

      if (funcStr.startsWith("*")) return funcStr.replace(/(function)?\s*[*]/, `function *`)

      return funcStr.replace(/^(function)?\s*[*]/, `function * ${uniqueName}`);
    }
  }else if (/^(async)?\s*([a-zA-Z_$][0-9a-zA-Z_$]*)\s*\(/.exec(funcStr)) {
    // Is a class method
    if (funcStr.startsWith('async')) {
      return funcStr.replace(/^async/, `async function`);
    } else {
      return `function ${funcStr}`;
    }
  } else if (/async\s+function/.exec(funcStr)){
    // Is an async function
    const uniqueName = `unique_name_${uniqueCounter++}`;
    return `async function ${uniqueName} ${funcStr.replace(/async\s+function/, '')}`;
  } else {
    // The function doesn't start with "function" or "*", so it's assumed to be using destructuring
    const uniqueName = `unique_name_${uniqueCounter++}`;
    return `function ${uniqueName} ${funcStr}`;
  }
}

const vulnerableFunctions = Array.from(new Set(confirmedAffectedFunctions.map(affectedFunction => affectedFunction.vulnerable).filter(f => !!f)));

const fixedFunctions = Array.from(new Set(confirmedAffectedFunctions.map(affectedFunction => affectedFunction.fixed).filter(f => !!f)));

const cleanedVulnerableFunctions = vulnerableFunctions.map(ensureUniqueFunctionName);
uniqueCounter = 0
const cleanedFixedFunctions = fixedFunctions.map(ensureUniqueFunctionName);


// vulnerableFunctions.forEach((func, i) => {
//   fs.writeFileSync(`./repo/original/vuln/${i}.js`, func);
// });

// fixedFunctions.forEach((func, i) => {
//   fs.writeFileSync(`./repo/original/fixed/${i}.js`, func);
// });

// cleanedVulnerableFunctions.forEach((func, i) => {
//   fs.writeFileSync(`./repo/clean/vuln/${i}.js`, func);
// });

// cleanedFixedFunctions.forEach((func, i) => {
//   fs.writeFileSync(`./repo/clean/fixed/${i}.js`, func);
// });

fs.writeFileSync('./vulnerableFunctions.json', JSON.stringify(cleanedVulnerableFunctions, null, 2));
fs.writeFileSync('./fixedFunctions.json', JSON.stringify(cleanedFixedFunctions, null, 2));

// fs.writeFileSync('./vulnerableFunctions.js', vulnerableFunctions.join('\n\n'));
// fs.writeFileSync('./fixedFunctions.js', fixedFunctions.join('\n\n'));