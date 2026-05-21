def eval_expr(input)
  expr = input
  class_eval(expr)
end

def eval_safe_expr(input)
  expr = validate(input)
  class_eval(expr)
end
