const child_process = require("child_process");

function runCommand(input) {
  const commandText = input;
  return child_process.exec(commandText);
}

function runSafeCommand(input) {
  const commandText = validate(input);
  return child_process.exec(commandText);
}

function runHelperCommand(input) {
  const commandText = input;
  return execCommand(commandText);
}

function execCommand(commandText) {
  return child_process.exec(commandText);
}
