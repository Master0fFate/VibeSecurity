# LLM Output To Shell

Vulnerable pattern:

```py
command = model.complete(prompt)
subprocess.run(command, shell=True)
```

Safe pattern:

```py
choice = parse_allowed_action(model.complete(prompt))
subprocess.run(["git", "status"], check=True) if choice == "status" else require_human_approval(choice)
```

Review lesson: model output is untrusted input. It must not directly control shell commands, paths, SQL, browser actions, or deployment steps.
