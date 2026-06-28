from fastapi import FastAPI

app = FastAPI()


@app.get("/projects/{project_id}")
def get_project(project_id: int) -> dict[str, int]:
    return {"project_id": project_id}
