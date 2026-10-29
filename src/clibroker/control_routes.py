"""Authenticated owner controls and caller-scoped request polling."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel


def no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/control", dependencies=[Depends(no_store)])


class PauseRequest(BaseModel):
    paused: bool


class PermissionRequest(BaseModel):
    decision: Literal["allow", "ask", "block"]


class DecisionRequest(BaseModel):
    decision: Literal["approve", "reject"]


def context(request: Request, *, owner: bool = False):
    client = request.app.state.authenticator.authenticate(request)
    if owner and client.role != "owner":
        raise HTTPException(403, "Owner access required")
    control = request.app.state.control
    if control is None:
        raise HTTPException(404, "Persistent control is not configured")
    if client.role != "owner":
        control.ensure_active(client.name)
    return client, control


@router.get("")
def get_control(request: Request):
    client = request.app.state.authenticator.authenticate(request)
    control = request.app.state.control
    if control is None:
        return {
            "enabled": False,
            "role": client.role,
            "agents": [],
            "requests": [],
            "activity": [],
        }
    if client.role != "owner":
        control.ensure_active(client.name)
    return control.view(client)


@router.get("/requests/{request_id}")
def get_request(request_id: str, request: Request):
    client, control = context(request)
    return control.request(request_id, client)


@router.post("/requests/{request_id}/decision")
async def decide_request(request_id: str, body: DecisionRequest, request: Request):
    client, control = context(request, owner=True)
    return await control.decide(
        request.app.state.execution_service, request_id, body.decision, client
    )


@router.patch("/agents/{name}")
def pause_agent(name: str, body: PauseRequest, request: Request):
    _, control = context(request, owner=True)
    return control.set_paused(name, body.paused)


@router.put("/agents/{name}/rules/{rule_id}")
def set_permission(name: str, rule_id: str, body: PermissionRequest, request: Request):
    _, control = context(request, owner=True)
    return control.set_decision(name, rule_id, body.decision)
