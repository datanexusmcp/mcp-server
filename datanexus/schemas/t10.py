from datanexus.schemas.base import DataNexusResponse

class T10Response(DataNexusResponse):
    tool_id: str = "T10"
