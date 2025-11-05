from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel


class MongoDBConfig(BaseModel):
    uri: str = "mongodb://localhost:27017/"
    database: str = "opengpts"


# Create a MongoDB client
client = AsyncIOMotorClient(MongoDBConfig().uri)

# Get the database
db = client[MongoDBConfig().database]


async def get_mongo_db():
    """Dependency to get the MongoDB database."""
    return db
