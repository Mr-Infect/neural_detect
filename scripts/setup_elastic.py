import asyncio
import json

from integrations.elasticsearch.client import close_client, get_client
from integrations.elasticsearch.pipelines import (
    install_ecs_index_template,
    install_ingest_pipelines,
)


async def main() -> None:
    try:
        client = get_client()
        info = await client.info()
        template = await install_ecs_index_template()
        installed = await install_ingest_pipelines()
        print(json.dumps({"cluster": info.body.get("cluster_name"), "template": template, "pipelines": installed}))
    finally:
        await close_client()

if __name__ == "__main__":
    asyncio.run(main())
