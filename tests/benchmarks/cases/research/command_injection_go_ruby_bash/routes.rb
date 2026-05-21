def run_command(input)
  command_text = input
  system(command_text)
end

def run_safe_command(input)
  command_text = validate(input)
  system(command_text)
end
