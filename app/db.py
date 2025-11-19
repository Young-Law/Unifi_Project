import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase, mapped_column
from sqlalchemy import Integer, String, LargeBinary, DateTime

logger = logging.getLogger("db")

class Base(DeclarativeBase):
    pass

DATABASE_URL = "sqlite:///./unifi_sessions.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

class StoredSession(Base):
    __tablename__ = "stored_sessions"

    id = mapped_column(Integer, primary_key=True, index=True)
    username = mapped_column(String)
    cookie_pickle = mapped_column(LargeBinary)
    csrf_token = mapped_column(String, nullable=True)
    created_at = mapped_column(DateTime)
    last_seen = mapped_column(DateTime)
    expires_at = mapped_column(DateTime, nullable=True)


def init_db():
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error - {e}")
