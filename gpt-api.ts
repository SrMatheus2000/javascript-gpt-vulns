import https from "node:https";
import dotenv from "dotenv";
import fs from 'fs/promises';

dotenv.config();

interface Answear {
  isVulnerable: boolean;
  CWEs?: string[];
  vulnerabilities?: string[];
  description?: string;
}

export const makeRequest = (prompt: string): Promise<string> => {
  let text = "";

  const body = JSON.stringify({
    model: "gpt-4",
    max_tokens: 2000,
    temperature: 0,
    // n: 1,
    stop: ["}"],
    stream: true,
    messages: [
      {
        role: "user",
        content: prompt,
      },
    ],
  });

  return new Promise((resolve, reject) => {
    const req = https.request(
      {
        hostname: "api.openai.com",
        port: 443,
        path: "/v1/chat/completions",
        method: "POST",
        timeout: 1000 * 60 * 5,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
        },
      },
      function (res) {
        res.on("data", (chunks) => {     
          for (const chunk of chunks.toString().split("\n")) {  
            if (chunk.toString().startsWith("data: ")) {
              const data = chunk.toString().replace(/^data: /, "");
              
              try {
                const content = JSON.parse(data)?.choices?.[0]?.delta?.content;
                if (content) {
                  text += content;
                }
              } catch (e) {}
            }
          }
        });
        res.on("end", () => {
          resolve(text + (text?.trim() ? "}" : ""))
        });
      }
    );

    req.on("error", (e) => {
      console.error(e)
      reject(e)
    });

    req.write(body);
    req.end();
  });
};

// const makePrompt4 = (vulnerableFunction: string) => `
// Ill give you a javascript function, tell me if you find any vulnerability on it, also provide me data for any CWEs you find, answear strictly in a format obbeying the following interface:
// interface Answear {
//   isVulnerable: boolean;
//   CWEs?: string[];
//   vulnerabilities?: string[];
//   description?: string;
// }

// ${vulnerableFunction}
// `;

const makePrompt = (vulnerableFunction: string) => `
Ill give you a javascript function, tell me if you find any vulnerability on it, also provide me data for any CWEs you find, make an answear in a json format with only the following fields:

isVulnerable: boolean;
CWEs?: string[];
vulnerabilities?: string[];
description?: string;

${vulnerableFunction}
`;

// const res = await makeRequest(`
// Ill give you a javascript function, tell me if you find any vulnerability on it, also provide me data for any CWEs you find, answear strictly in a format obbeying the following interface:
// interface Answear {
//   isVulnerable: boolean;
//   CWEs?: string[];
//   vulnerabilities?: string[];
//   description?: string;
// }

// function htmlEncode(text) {
//   return document.createElement('a').appendChild( document.createTextNode(text) ).parentNode.innerHTML;
// }
// `)
// console.log(res);

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

const vulnerablesFile = await fs.readFile('./vulnerableFunctions.json', 'utf8');

const vulnerables = JSON.parse(vulnerablesFile) as string[];

await fs.mkdir('./gpt-4-answears-2/vuln', { recursive: true });
await fs.mkdir('./gpt-4-answears-2/fixed', { recursive: true });

let withTooManyTokens = [];
let withErrors = [];

const CWEs = new Set<string>();

let truePositives = 0;
let falsePositives = 0;
let trueNegatives = 0;
let falseNegatives = 0;

let reTries = 0;

for (let i = 0; i < vulnerables.length; i++) {
  const vulnerable = vulnerables[i];
  console.log('vuln ' + i);
  try {
    const res = await makeRequest(makePrompt(vulnerable));
    await fs.writeFile(`./gpt-4-answears-2/vuln/${i}.json`, res);
    if (res.trim()) {
      try {
        const answear = JSON.parse(res) as Answear;
        if (answear.isVulnerable) {
          truePositives++;
        } else {
          falseNegatives++;
        }
        answear.CWEs?.forEach(CWE => CWEs.add(CWE));
        reTries = 0;
      } catch (error) {
        if (reTries < 5) {
          i--;
          reTries++;
        } else {
          withErrors.push(i);
          console.error(error);
          reTries = 0;
        }
      }
    } else {
      withTooManyTokens.push(i);
    }
    // if (i % 5 === 0) await sleep(1000 * 3);
  } catch (error) {
    console.error(i, error);
  }
}

console.log('withTooManyTokens', withTooManyTokens.length, withTooManyTokens);
console.log('withErrors', withErrors.length, withErrors);

withTooManyTokens = []
withErrors = []

const fixedFile = await fs.readFile('./fixedFunctions.json', 'utf8');

const fixeds = JSON.parse(fixedFile) as string[];

for (let j = 0; j < fixeds.length; j++) {
  const fixed = fixeds[j];
  console.log('fixed ' + j);
  try {
    const res = await makeRequest(makePrompt(fixed));
    await fs.writeFile(`./gpt-4-answears-2/fixed/${j}.json`, res);
    if (res.trim()) {
      try {
        const answear = JSON.parse(res) as Answear;
        if (answear.isVulnerable) {
          falsePositives++;
        } else {
          trueNegatives++;
        }
        answear.CWEs?.forEach(CWE => CWEs.add(CWE));
        reTries = 0;
      } catch (error) {
        if (reTries < 5) {
          j--;
          reTries++;
        } else {
          withErrors.push(j);
          console.error(error);
          reTries = 0;
        }
      }
    } else {
      withTooManyTokens.push(j);
    }
    // if (i % 5 === 0) await sleep(1000 * 3);
  } catch (error) {
    console.error(j, error);
  }
}

console.log('withTooManyTokens', withTooManyTokens.length, withTooManyTokens);
console.log('withErrors', withErrors.length, withErrors);

console.log('truePositives', truePositives);
console.log('falsePositives', falsePositives);
console.log('trueNegatives', trueNegatives);
console.log('falseNegatives', falseNegatives);

console.log('CWEs', CWEs.size, Array.from(CWEs).join(', '));