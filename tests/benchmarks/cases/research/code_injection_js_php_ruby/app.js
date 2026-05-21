function evalExpr(input, vm) {
  const expr = input;
  return vm.runInNewContext(expr);
}

function evalSafeExpr(input) {
  const expr = validate(input);
  return eval(expr);
}
