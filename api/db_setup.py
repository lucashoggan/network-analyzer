from os import environ

from databases import Database
from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    Column,
    ForeignKey,
    Integer,
    MetaData,
    String,
    create_engine,
    text,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column

DATABASE_URL = environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("No database url specified in environment varible")
SYNC_DB_URL = DATABASE_URL.replace("+asyncpg", "")

database = Database(DATABASE_URL)

metadata = MetaData()
Base = declarative_base(metadata=metadata)


def init_db():
    if DATABASE_URL:
        engine = create_engine(SYNC_DB_URL)
        with engine.begin() as connection:
            metadata.create_all(bind=connection)


class LogFile(Base):
    __tablename__ = "log_files"
    id = mapped_column(Integer, primary_key=True, index=True)
    filename = mapped_column(String(100))
    processed = mapped_column(Boolean, nullable=False, server_default=text("false"))


class LogSection(Base):
    __tablename__ = "log_sections"
    id = mapped_column(Integer, primary_key=True, index=True)
    file_id = mapped_column(ForeignKey("log_files.id"))
    embedding = mapped_column(Vector(1536), nullable=True)
    start_packet_number = mapped_column(Integer)
    end_packet_number = mapped_column(Integer)
