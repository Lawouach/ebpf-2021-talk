import asyncio
import random


from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


async def index(request: Request) -> JSONResponse:
    # fake some latency
    await asyncio.sleep(0 if random.random() < 0.99 else random.random())

    # fake some errors
    if random.random() > 0.993:
        return JSONResponse({'error': 'boom'}, status_code=500)

    return JSONResponse({'hello': 'world'})


app = Starlette(debug=True, routes=[
    Route('/', index),
])
