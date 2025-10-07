from sqlmodel import SQLModel, Field, Relationship

class RandomState(SQLModel, table = True):
    __tablename__ = "random_state"
    id: int = Field(primary_key=True)
    seed: int = Field(default=123)