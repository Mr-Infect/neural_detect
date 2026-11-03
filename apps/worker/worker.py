import asyncio
import logging


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("neural_detect.worker").info("Worker is running; queue handlers are not configured yet.")
    while True:
        await asyncio.sleep(60)

if __name__ == "__main__":
    asyncio.run(main())
