import asyncio
from aiohttp import web
import websockets
import jwt
import json


SECRET_KEY = "your_secret_key"

users_db = {"a": "1", "b": "2"}
connected_clients = {}


def create_token(username: str) -> str:
    return jwt.encode({"username": username}, SECRET_KEY, algorithm="HS256")

def verify_token(token: str):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return decoded["username"]
    except jwt.ExpiredSignatureError:
        raise web.HTTPUnauthorized(reason="Token expired")
    except jwt.InvalidTokenError:
        raise web.HTTPUnauthorized(reason="Invalid token")

async def hello():
    return web.Response(text="Hello, world")

async def handle_http_request(request):
    if request.body_exists:
        body = await request.json()
        username = body["username"]
        password = body["password"]
        if username in users_db and users_db[username] == password:
            token = create_token(username)
            data = {"token": token}
            return web.json_response(data)
        else:
            raise web.HTTPUnauthorized(reason="Invalid credentials")

async def handle_websocket(websocket):
    try:
        while True:
            message = await websocket.recv()
            data = json.loads(message)
            token = data["token"]
            username = verify_token(token)
            if data["type"] == "join":
                connected_clients[username] = websocket
                print(f"User {username} connected.")
                for user, client in connected_clients.items():
                    if user == username:
                        await client.send(json.dumps({"type": "clients", "username": username, "clients": [x for x in connected_clients if x!=username]}))
                    elif user != username:
                        await client.send(json.dumps({"type": "spawn", "username": username, "spawn": username}))
            elif data["type"] == "chat":
                for user, client in connected_clients.items():
                    if user != username:
                        await client.send(json.dumps({"type": "chat", "username": username, "message": data["message"]}))
            elif data["type"] == "move":
                for user, client in connected_clients.items():
                    if user != username:
                        await client.send(json.dumps({"type": "move", "username": username, "position": data["position"], "rotation": data["rotation"]}))
            elif data["type"] == "voice":
                for user, client in connected_clients.items():
                    if user != username:
                        await client.send(json.dumps({"type": "voice", "username": username, "voice": data["voice"]}))
    except websockets.ConnectionClosed:
        print("Connection closed")
    finally:
        del connected_clients[username]

async def main():
    app = web.Application()
    app.add_routes([web.get('/', hello)])
    app.add_routes([web.post('/login', handle_http_request)])
    runner = web.AppRunner(app)
    await runner.setup()
    http_server = web.TCPSite(runner, "0.0.0.0", 8080)

    websocket_server = websockets.serve(handle_websocket, "0.0.0.0", 8765)

    await asyncio.gather(
        http_server.start(),
        websocket_server
    )

    print("HTTP server started on http://localhost:8080")
    print("WebSocket server started on ws://localhost:8765")

    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
