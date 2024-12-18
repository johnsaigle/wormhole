const { parse } = require("@solidity-parser/parser");
const fs = require("fs");
const path = require("path");

// Directories to search in
const directories = [
  "../contracts",
  "../forge-scripts"
];

// Function to check if file is a Solidity file
function isSolidityFile(filename) {
  return filename.endsWith('.sol');
}

// Function to recursively get all Solidity files in a directory
function getSolidityFiles(dir) {
  let results = [];
  try {
    const files = fs.readdirSync(dir);
    
    for (const file of files) {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      
      if (stat.isDirectory()) {
        // Recursively search subdirectories
        results = results.concat(getSolidityFiles(filePath));
      } else if (isSolidityFile(file)) {
        results.push(filePath);
      }
    }
  } catch (err) {
    console.log(`Could not read directory ${dir}: ${err.message}`);
  }
  return results;
}

// Function to check syntax of a single file
function checkSyntax(filePath) {
  try {
    const source = fs.readFileSync(filePath, "utf8");
    parse(source);
    console.log(`✅ ${filePath}: No syntax errors found`);
    return true;
  } catch (e) {
    const location = e.line ? ` at line ${e.line}${e.column ? `, column ${e.column}` : ''}` : '';
    console.error(`❌ ${filePath}:\n   Syntax error${location}: ${e.message}`);
    return false;
  }
}

// Main function
function main() {
  let totalFiles = 0;
  let filesWithErrors = 0;

  // Process each directory
  for (const dir of directories) {
    const files = getSolidityFiles(dir);
    totalFiles += files.length;
    
    for (const file of files) {
      if (!checkSyntax(file)) {
        filesWithErrors++;
      }
    }
  }

  // Print summary
  console.log("\nSummary:");
  console.log(`Total files checked: ${totalFiles}`);
  console.log(`Files with errors: ${filesWithErrors}`);
  console.log(`Files without errors: ${totalFiles - filesWithErrors}`);
  
  // Exit with error code if any files had syntax errors
  process.exit(filesWithErrors > 0 ? 1 : 0);
}

main();
