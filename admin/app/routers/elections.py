from datetime import datetime
from enum import Enum
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()


class ExtensionPolicy(str, Enum):
    required = "required"
    recommended = "recommended"
    disabled = "disabled"


class ElectionCreate(BaseModel):
    name: str
    date: str
    polls_open: str
    polls_close: str
    extension_policy: ExtensionPolicy = ExtensionPolicy.required


class Party(BaseModel):
    name: str
    candidates: list[str] = []


class Election(BaseModel):
    id: str
    name: str
    date: str
    polls_open: str
    polls_close: str
    extension_policy: ExtensionPolicy
    parties: list[Party]
    status: str
    created_at: datetime


# In-memory store (PostgreSQL in production)
_elections: dict[str, Election] = {}
_next_id = 1


@router.post("/elections", status_code=201)
async def create_election(req: ElectionCreate):
    global _next_id
    election_id = f"election-{_next_id}"
    _next_id += 1

    election = Election(
        id=election_id,
        name=req.name,
        date=req.date,
        polls_open=req.polls_open,
        polls_close=req.polls_close,
        extension_policy=req.extension_policy,
        parties=[],
        status="draft",
        created_at=datetime.now(),
    )
    _elections[election_id] = election
    return election


@router.get("/elections")
async def list_elections():
    return list(_elections.values())


@router.get("/elections/{election_id}")
async def get_election(election_id: str):
    if election_id not in _elections:
        raise HTTPException(status_code=404, detail="Election not found")
    return _elections[election_id]


@router.post("/elections/{election_id}/parties")
async def add_party(election_id: str, party: Party):
    if election_id not in _elections:
        raise HTTPException(status_code=404, detail="Election not found")
    election = _elections[election_id]
    if election.status != "draft":
        raise HTTPException(status_code=409, detail="Cannot modify a non-draft election")
    if len(election.parties) >= 50:
        raise HTTPException(status_code=422, detail="Maximum 50 parties per election")
    election.parties.append(party)
    return {"parties": len(election.parties)}


@router.post("/elections/{election_id}/activate")
async def activate_election(election_id: str):
    if election_id not in _elections:
        raise HTTPException(status_code=404, detail="Election not found")
    election = _elections[election_id]
    if not election.parties:
        raise HTTPException(status_code=422, detail="Election must have at least one party")
    election.status = "active"
    return election


@router.post("/elections/{election_id}/seal")
async def seal_election(election_id: str):
    if election_id not in _elections:
        raise HTTPException(status_code=404, detail="Election not found")
    election = _elections[election_id]
    if election.status != "active":
        raise HTTPException(status_code=409, detail="Only active elections can be sealed")
    election.status = "sealed"
    return election
