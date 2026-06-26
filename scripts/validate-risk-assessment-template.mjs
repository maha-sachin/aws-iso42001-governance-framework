import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const templatePath = path.join(repoRoot, "docs", "responsible-ai-risk-assessment-template.md");

if (!existsSync(templatePath)) {
  console.error(`Template file not found: ${templatePath}`);
  process.exit(1);
}

const content = readFileSync(templatePath, "utf8");
const requiredSections = [
  "## 1. System Information",
  "## 2. Risk Assessment",
  "## 3. Overall Assessment",
  "## 4. Scoring Guidance",
  "## 5. Sign-Off"
];

const requiredDimensions = [
  "Fairness",
  "Accountability",
  "Transparency",
  "Safety",
  "Data Use",
  "Regulatory Exposure"
];

const missingSections = requiredSections.filter((section) => !content.includes(section));
const missingDimensions = requiredDimensions.filter((dimension) => !content.includes(dimension));

if (missingSections.length > 0 || missingDimensions.length > 0) {
  if (missingSections.length > 0) {
    console.error(`Missing required sections: ${missingSections.join(", ")}`);
  }
  if (missingDimensions.length > 0) {
    console.error(`Missing required dimensions: ${missingDimensions.join(", ")}`);
  }
  process.exit(1);
}

console.log("Responsible AI risk assessment template validation passed.");
