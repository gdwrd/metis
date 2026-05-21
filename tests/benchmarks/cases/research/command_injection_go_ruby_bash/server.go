package main

func RunCommand(input string) {
    cmd := input
    exec.Command("sh", "-c", cmd).Run()
}

func RunSafeCommand(input string) {
    cmd := validate(input)
    exec.Command("sh", "-c", cmd).Run()
}
