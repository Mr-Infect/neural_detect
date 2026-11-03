"""Bridge Docker clients to the loopback-only WSL Ollama service."""
import asyncio
import logging

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ollama-relay")

async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection("127.0.0.1", 11434)
        async def pipe(source: asyncio.StreamReader, target: asyncio.StreamWriter) -> None:
            while chunk := await source.read(65536):
                target.write(chunk)
                await target.drain()
        tasks = [asyncio.create_task(pipe(reader, upstream_writer)),
                 asyncio.create_task(pipe(upstream_reader, writer))]
        _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        upstream_writer.close()
        await upstream_writer.wait_closed()
    except (ConnectionError, OSError) as exc:
        log.warning("Ollama relay upstream unavailable: %s", exc)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass

async def main() -> None:
    server = await asyncio.start_server(handle, "172.17.0.1", 11435)
    log.info("Private Ollama relay listening on Docker bridge gateway 172.17.0.1:11435")
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
