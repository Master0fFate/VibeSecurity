# FastAPI Object-Level Authorization

Vulnerable pattern:

```py
@app.get("/projects/{project_id}")
def get_project(project_id: int) -> Project:
    return repository.get_project(project_id)
```

Safe pattern:

```py
@app.get("/projects/{project_id}")
def get_project(project_id: int, user: User = Depends(require_user)) -> Project:
    project = repository.get_project(project_id)
    require_project_access(user, project)
    return project
```

Review lesson: authentication proves identity; object-level authorization proves this identity may access this object.
