# Rest of your imports
import discord
from discord import app_commands
from discord.ext import commands, tasks
from discord.ui import View, Button
import aiohttp
import os
import random
import string
import re
import asyncio
from io import BytesIO
from urllib.parse import unquote, urlparse, parse_qs
import base64
import json
import time
import traceback
import sys
from typing import Optional, Dict
from datetime import datetime, timezone

# --- Setup ---
import os
TOKEN = os.environ.get("DISCORD_BOT_TOKEN")
if not TOKEN:
    raise ValueError("No token found. Make sure DISCORD_BOT_TOKEN is set in Replit secrets")
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

# --- On Ready Event to Sync Commands ---
@bot.event
async def on_ready():
    print(f'Logged in as {bot.user} (ID: {bot.user.id})')
    print("Attempting to sync commands...")
    try:
        synced = await tree.sync()
        print(f"Synced {len(synced)} command(s).")
    except Exception as e:
        print("Failed to sync commands.")
        traceback.print_exc()

    # Start the auto-claim task if there are users to track
    if autoclaim_users:
        if not claim_rewards_loop.is_running():
            claim_rewards_loop.start()

# --- Debugging for Command Errors ---
@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    print(f"Ignoring exception in command {ctx.command}:", file=sys.stderr)
    traceback.print_exception(type(error), error, error.__traceback__, file=sys.stderr)
    await ctx.send(f"❌ An internal error occurred while running that command. The developer has been notified.")

# --- Session Data Persistence ---
SESSION_FILE = "session.json"

def load_session_data():
    """Loads session data from a JSON file."""
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, 'r') as f:
            try:
                data = json.load(f)
                return data
            except json.JSONDecodeError:
                print("WARNING: session.json file is corrupt, starting with an empty session.")
                return {}
    return {}

def save_session_data():
    """Saves session data to a JSON file."""
    with open(SESSION_FILE, 'w') as f:
        json.dump({
            "user_session_data": user_session_data,
            "autoclaim_users": list(autoclaim_users)
        }, f)

# Centralized storage for user-specific data (token, user_id, etc.)
session_data = load_session_data()
user_session_data = session_data.get("user_session_data", {})
autoclaim_users = set(session_data.get("autoclaim_users", []))
print(f"DEBUG: Loaded session data on startup: {user_session_data}")
print(f"DEBUG: Loaded autoclaim users on startup: {autoclaim_users}")

# --- Caches and Storage ---
metadata_cache = {}

# Track players' online status
tracked_players: Dict[str, dict] = {}
OWNER_ID = 1398012286966300798

# --- Helper Functions ---
def extract_strings(data: bytes):
    """
    Extracts printable ASCII strings from binary data.
    """
    pattern = re.compile(rb'[\x20-\x7E]{4,}')
    strings, offsets = [], []
    for m in pattern.finditer(data):
        offsets.append(m.start())
        strings.append(m.group().decode("utf-8", errors="ignore"))
    return strings, offsets

async def fetch_pixeldrain_file(key: str):
    """
    Fetches a file from Pixeldrain using its key.
    """
    url = f"https://pixeldrain.com/api/file/{key}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                return None, resp.status
            return await resp.read(), 200

def extract_tokens_from_data_url(xmod_url: str):
    """
    Extracts JWT tokens and potentially username from a URL's 'data' query parameter.
    Returns (username, auth_token, refresh_token) or (None, None, None)
    """
    if "?data=" not in xmod_url:
        return None, None, None
    query = urlparse(xmod_url).query
    params = parse_qs(query)
    if "data" not in params:
        return None, None, None
    decoded = unquote(params["data"][0])
    try:
        data_array = json.loads(decoded)
        if isinstance(data_array, list) and len(data_array) >= 3:
            username = data_array[0]
            auth_token = data_array[1]
            refresh_token = data_array[2]
            return username, auth_token, refresh_token
    except json.JSONDecodeError:
        pass
    return None, None, None

def is_jwt_expired(token: str) -> bool:
    """
    Checks if a JWT token is expired based on its 'exp' claim.
    Returns True if expired or invalid, False otherwise.
    """
    try:
        payload_b64 = token.split('.')[1]
        # Add padding if necessary for base64 decoding
        padding = '=' * (-len(payload_b64) % 4)
        payload_b64 += padding
        decoded_bytes = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(decoded_bytes)
        exp = payload.get("exp")
        if exp is None:
            return False
        now = int(time.time())
        return now >= exp
    except Exception as e:
        print(f"DEBUG: JWT expiration check failed: {e}")
        return True

async def refresh_token(refresh_token: str) -> tuple[str | None, str | None]:
    """
    Uses the refresh token to get a new auth and refresh token.
    Returns (new_auth_token, new_refresh_token) or (None, None).
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account/session/refresh"
    headers = {
        "Authorization": "Basic NlVSdVRTbERLS2ZZYnVEVzo=",
        "Content-Type": "application/json"
    }
    data = {"token": refresh_token}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=data) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                return response_data.get("token"), response_data.get("refresh_token")
            else:
                print(f"DEBUG: Token refresh failed. Status: {resp.status}, Response: {await resp.text()}")
                return None, None

async def get_user_id(auth_token: str) -> str | None:
    """
    Fetches the user_id associated with the provided auth token.
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account"
    headers = {"Authorization": f"Bearer {auth_token}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                return response_data.get("user", {}).get("id")
            else:
                print(f"DEBUG: get_user_id failed. Status: {resp.status}, Response: {await resp.text()}")
                return None

async def get_nakama_storage_data_for_user_id(auth_token: str, user_id: str, key: str) -> dict | None:
    """
    Fetches data from a user's Nakama storage using their user_id.
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/storage"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    body = {
        "object_ids": [
            {
                "collection": "user_inventory",
                "key": key,
                "user_id": user_id
            }
        ]
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=body) as resp:
            if resp.status != 200:
                print(f"DEBUG: get_nakama_storage_data failed for key '{key}'. Status: {resp.status}, Response: {await resp.text()}")
                return None
            response_data = await resp.json()
            objects = response_data.get("objects", [])
            if not objects:
                print(f"DEBUG: No objects found for key '{key}' in Nakama storage.")
                return None
            value_str = objects[0].get("value")
            if not value_str:
                print(f"DEBUG: 'value' field missing for key '{key}' in Nakama storage response.")
                return None
            return json.loads(value_str)

async def put_nakama_storage_data(auth_token: str, key: str, value: dict) -> bool:
    """
    Puts data into a user's Nakama storage.
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/storage"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
    }
    body = {
        "objects": [{
            "collection": "user_inventory",
            "key": key,
            "permission_read": 1,
            "permission_write": 1,
            "value": json.dumps(value)
        }]
    }

    async with aiohttp.ClientSession() as session:
        async with session.put(url, headers=headers, json=body) as resp:
            if resp.status != 200:
                print(f"DEBUG: put_nakama_storage_data failed for key '{key}'. Status: {resp.status}, Response: {await resp.text()}")
                return False
            print(f"DEBUG: put_nakama_storage_data success for key '{key}'. Status: {resp.status}")
            return True

async def delete_nakama_storage_data(auth_token: str, collection: str, key: str) -> bool:
    """
    Deletes data from a user's Nakama storage.
    """
    url = f"https://animalcompany.us-east1.nakamacloud.io/v2/storage?collection={collection}&key={key}"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json"
    }

    async with aiohttp.ClientSession() as session:
        async with session.delete(url, headers=headers) as resp:
            if resp.status == 204:
                print(f"DEBUG: delete_nakama_storage_data success for collection '{collection}', key '{key}'.")
                return True
            else:
                error_detail = await resp.text()
                print(f"DEBUG: delete_nakama_storage_data failed for collection '{collection}', key '{key}'. Status: {resp.status}, Response: {error_detail}")
                return False

async def get_nakama_wallet_data(auth_token: str) -> dict | None:
    """
    Fetches the user's wallet data from Nakama.
    Returns a dictionary with wallet balances or None on failure.
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account"
    headers = {"Authorization": f"Bearer {auth_token}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                wallet_str = response_data.get("wallet")
                if wallet_str:
                    return json.loads(wallet_str)
            print(f"DEBUG: get_nakama_wallet_data failed. Status: {resp.status}, Response: {await resp.text()}")
            return None

async def update_nakama_wallet(auth_token: str, new_wallet_data: dict) -> bool:
    """
    Updates the user's wallet data on Nakama.
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account/wallet"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    body = {"changeset": {"set": new_wallet_data}}

    async with aiohttp.ClientSession() as session:
        async with session.put(url, headers=headers, json=body) as resp:
            if resp.status == 204:
                print(f"DEBUG: Wallet update successful.")
                return True
            else:
                error_detail = await resp.text()
                print(f"DEBUG: Wallet update failed. Status: {resp.status}, Response: {error_detail}")
                return False

async def get_nakama_mining_balance(auth_token: str) -> dict | None:
    """
    Fetches the user's mining balance from Nakama.
    Returns a dictionary with mining balances or None on failure.
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/rpc/mining.balance"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                payload_str = response_data.get("payload")
                if payload_str:
                    return json.loads(payload_str)
            print(f"DEBUG: get_nakama_mining_balance failed. Status: {resp.status}, Response: {await resp.text()}")
            return None

async def get_user_data(auth_token: str, player_identifier: str) -> dict | None:
    """
    Attempts to find a user by their username or user ID.
    Returns user data or None if not found.
    """
    print(f"DEBUG: Attempting to get user data for identifier: '{player_identifier}'")
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', player_identifier):
        body = {"user_ids": [player_identifier]}
        print(f"DEBUG: get_user_data using User ID lookup. Body: {body}")
    else:
        body = {"usernames": [player_identifier]}
        print(f"DEBUG: get_user_data using Username lookup. Body: {body}")

    url = "https://animalcompany.us-east1.nakamacloud.io/v2/users"
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=body) as resp:
            response_text = await resp.text()
            print(f"DEBUG: get_user_data response status: {resp.status}, response: {response_text}")
            if resp.status == 200:
                data = json.loads(response_text)
                users = data.get("users", [])
                return users[0] if users else None
    return None

async def claim_mining_rewards(auth_token: str) -> dict | None:
    """
    Claims the user's mining rewards.
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/rpc/mining.claim"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    # This RPC call requires an empty JSON body
    body = {}

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=body) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                payload_str = response_data.get("payload")
                if payload_str:
                    return json.loads(payload_str)
            else:
                print(f"DEBUG: claim_mining_rewards failed. Status: {resp.status}, Response: {await resp.text()}")
            return None


# --- Metadata View Classes ---
class MetadataView(View):
    def __init__(self, user_id, message=None):
        super().__init__(timeout=120)
        self.user_id = user_id
        self.message = message

    async def interaction_check(self, inter: discord.Interaction) -> bool:
        if inter.user.id != self.user_id:
            return False
        return True

    @discord.ui.button(label="⏮️ Previous", style=discord.ButtonStyle.secondary)
    async def previous(self, inter: discord.Interaction, btn: Button):
        data = metadata_cache[self.user.id]
        if data["page"] > 0:
            data["page"] -= 1
            await update_metadata_message(inter, data, self.message)

    @discord.ui.button(label="⏭️ Next", style=discord.ButtonStyle.secondary)
    async def next(self, inter: discord.Interaction, btn: Button):
        data = metadata_cache[self.user.id]
        max_page = (len(data["strings"]) - 1) // 5
        if data["page"] < max_page:
            data["page"] += 1
            await update_metadata_message(inter, data, self.message)

class SaveEditView(View):
    def __init__(self, user_id, index, bot_message):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.index = index
        self.bot_message = bot_message

    async def interaction_check(self, inter: discord.Interaction) -> bool:
        if inter.user.id != self.user_id:
            return False
        return True

    @discord.ui.button(label="💾 Save", style=discord.ButtonStyle.success)
    async def save(self, inter: discord.Interaction, btn: Button):
        def check(m):
            return (
                m.author.id == self.user_id
                and m.reference
                and m.reference.message_id == self.bot_message.id
            )

        try:
            reply = await bot.wait_for('message', timeout=120.0, check=check)
        except asyncio.TimeoutError:
            return await inter.followup.send("❌ Timeout: you did not reply in time.", ephemeral=True)

        new_val = reply.content.strip()
        user_data = metadata_cache[self.user_id]
        old_str = user_data["strings"][self.index]
        orig_len = len(old_str.encode("utf-8"))
        enc = new_val.encode("utf-8")
        if len(enc) > orig_len:
            return await inter.followup.send("❌ New string too long.", ephemeral=True)

        user_data["strings"][self.index] = new_val
        mutated = bytearray(user_data["original"])
        off = user_data["offsets"][self.index]
        padded = enc.ljust(orig_len, b'\x00')
        mutated[off:off+orig_len] = padded

        bio = BytesIO(mutated)
        bio.seek(0)
        dm = await inter.user.create_dm()
        await dm.send(content=f"Here is your modified metadata (string #{self.index+1}):",
                      file=discord.File(fp=bio, filename="modified_metadata.dat"))
        await inter.followup.send("✅ Sent to your DMs!", ephemeral=True)

async def update_metadata_message(inter: discord.Interaction, data, message: discord.Message):
    page = data["page"]
    start, end = page*5, (page+1)*5
    slice_ = data["strings"][start:end]
    content = f"📄 **Page {page + 1}**\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(slice_, start+1))
    view = MetadataView(inter.user.id, message)
    await inter.response.edit_message(content=content, view=view)


class ConfirmWipeView(View):
    def __init__(self, user_id):
        super().__init__(timeout=60)
        self.user_id = user_id
        self.result = None

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user.id != self.user_id:
            return False
        return True

    @discord.ui.button(label="Confirm Wipe", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: Button):
        self.result = True
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(view=self)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.grey)
    async def cancel(self, interaction: discord.Interaction, button: Button):
        self.result = False
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(content="Account wipe cancelled.", view=self)
        self.stop()
        
# --- Discord Commands ---
@tree.command(name="load_dat", description="Load a .dat file from Pixeldrain")
@app_commands.describe(pixeldrain_url="Pixeldrain URL")
async def load_dat(inter: discord.Interaction, pixeldrain_url: str):
    await inter.response.defer(ephemeral=True)
    if "pixeldrain.com" not in pixeldrain_url:
        return await inter.followup.send("❌ Invalid Pixeldrain URL.")
    key = pixeldrain_url.rstrip("/").split("/")[-1]
    data, status = await fetch_pixeldrain_file(key)
    if not data:
        return await inter.followup.send(f"❌ Download failed: HTTP {status}")
    strings, offsets = extract_strings(data)
    metadata_cache[inter.user.id] = {"original": data, "strings": strings, "offsets": offsets, "page": 0}
    await inter.followup.send(f"✅ Loaded {len(strings)} strings. Use /show_dat to view.", ephemeral=True)

@tree.command(name="show_dat", description="Show editable metadata strings")
async def show_dat(inter: discord.Interaction):
    if inter.user.id not in metadata_cache:
        return await inter.response.send_message("⚠️ Load a .dat first with /load_dat.", ephemeral=True)

    data = metadata_cache[inter.user.id]
    data["page"] = 0
    slice_ = data["strings"][:5]
    content = f"📄 **Page 1**\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(slice_, 1))
    view = MetadataView(inter.user.id)
    await inter.response.send_message(content, view=view, ephemeral=True)

@tree.command(name="edit_dat", description="Edit a specific metadata string")
@app_commands.describe(string_number="1-based index")
async def edit_dat(inter: discord.Interaction, string_number: int):
    if inter.user.id not in metadata_cache:
        return await inter.response.send_message("⚠️ Load a .dat first with /load_dat.", ephemeral=True)
    
    data = metadata_cache[inter.user.id]
    idx = string_number - 1
    
    if idx < 0 or idx >= len(data["strings"]):
        return await inter.response.send_message(f"❌ Invalid string number. Please provide a number between 1 and {len(data['strings'])}.", ephemeral=True)
    
    current = data["strings"][idx]
    view = SaveEditView(inter.user.id, idx, None)
    
    msg = await inter.response.send_message(
        f"✏️ **Editing string #{string_number}:**\n\n{current}\n\nReply to this message, then click **Save**.",
        view=view,
        ephemeral=True
    )
    view.bot_message = await inter.original_response()

@tree.command(name="scan_apk", description="Scan APK metadata from Pixeldrain")
@app_commands.describe(pixeldrain_url="Pixeldrain URL")
async def scan_apk(inter: discord.Interaction, pixeldrain_url: str):
    await inter.response.defer(ephemeral=True)
    if "pixeldrain.com" not in pixeldrain_url:
        return await inter.followup.send("❌ Invalid Pixeldrain URL.")
    key = pixeldrain_url.rstrip("/").split("/")[-1]
    data, status = await fetch_pixeldrain_file(key)
    if not data:
        return await inter.followup.send(f"❌ Download failed: HTTP {status}")
    await inter.followup.send(f"📦 APK size: {len(data)} bytes.", ephemeral=True)

@tree.command(name="generate_nitro", description="Generate a fake Nitro code")
async def generate_nitro(inter: discord.Interaction):
    await inter.response.defer()
    code = ''.join(random.choices(string.ascii_letters + string.digits, k=24))
    await inter.followup.send(f"https://discord.gift/{code}")

@tree.command(name="clearmessage", description="Clear all bot messages in this channel")
async def clearmessage(inter: discord.Interaction):
    await inter.response.defer(ephemeral=True)

    deleted = 0
    async for msg in inter.channel.history(limit=None, oldest_first=False):
        if msg.author.id == bot.user.id:
            try:
                await msg.delete()
                deleted += 1
                await asyncio.sleep(0.3)
            except discord.HTTPException:
                pass
    await inter.followup.send(f"✅ Deleted {deleted} messages.", ephemeral=True)

@tree.command(name="acplayer", description="Sets your auth token using an xmod URL. You must get one from https://ac.xmodding.org/api")
@app_commands.describe(xmod_url="The URL from the ACTools API page after clicking Copy ShareURL")
async def acplayer(interaction: discord.Interaction, xmod_url: str):
    await interaction.response.defer(ephemeral=True)

    username, auth_token, refresh_token = extract_tokens_from_data_url(xmod_url)

    if not auth_token or not refresh_token:
        await interaction.followup.send("❌ Invalid xmod URL. Please provide the full URL from the ACTools API page.", ephemeral=True)
        return

    nakama_user_id = await get_user_id(auth_token)
    if not nakama_user_id:
        await interaction.followup.send("❌ Failed to get user ID with the provided token. The token may be expired or invalid. Please generate a new URL and try again.", ephemeral=True)
        return

    user_session_data[interaction.user.id] = {
        "auth_token": auth_token,
        "refresh_token": refresh_token,
        "nakama_user_id": nakama_user_id
    }
    print(f"DEBUG: Successfully stored token for user {interaction.user.id}")

    save_session_data()
    print(f"DEBUG: Saved session data to file.")

    await interaction.followup.send(f"✅ Successfully authenticated as **{username}**! Your auth_token and user_id are now saved. You can now use other commands like /get_my_stash or /add-item-to-stash.", ephemeral=True)

@tree.command(name="changedisplayname", description="Changes your in-game display name in Animal Company.")
@app_commands.describe(new_name="The new display name you want to use.")
async def changedisplayname(interaction: discord.Interaction, new_name: str):
    await interaction.response.defer(ephemeral=True)

    user_id = interaction.user.id
    if user_id not in user_session_data:
        await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]

    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token
            save_session_data()
        else:
            await interaction.followup.send("❌ Your session has expired and could not be refreshed. Please run `/acplayer` again to re-authenticate.", ephemeral=True)
            del user_session_data[user_id]
            save_session_data()
            return

    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    body = {"display_name": new_name}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.put(url, headers=headers, json=body) as resp:
                if resp.status == 204:
                    await interaction.followup.send(f"✅ Your display name has been changed to `{new_name}`! You may need to restart your game client to see the change.", ephemeral=True)
                else:
                    error_detail = await resp.text()
                    await interaction.followup.send(f"❌ Failed to change your display name. Status: `{resp.status}`. Error: `{error_detail}`", ephemeral=True)
        except aiohttp.ClientError as e:
            await interaction.followup.send(f"❌ An error occurred while communicating with the server: `{e}`", ephemeral=True)

@tree.command(name="editloadout", description="Edits your in-game loadout with a JSON file.")
@app_commands.describe(loadout_file="A JSON file containing your new loadout data.")
async def editloadout(interaction: discord.Interaction, loadout_file: discord.Attachment):
    await interaction.response.defer(ephemeral=True)
    user_id = interaction.user.id
    if user_id not in user_session_data or is_jwt_expired(user_session_data[user_id]["auth_token"]):
        await interaction.followup.send("❌ Your session has expired or you are not authenticated. Please run /acplayer first.", ephemeral=True)
        return

    try:
        loadout_data = await loadout_file.read()
        loadout_json = json.loads(loadout_data)
    except Exception as e:
        await interaction.followup.send(f"❌ Failed to read or parse the JSON file: {e}", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    key = "gameplay_loadout"

    if await put_nakama_storage_data(auth_token, key, loadout_json):
        await interaction.followup.send("✅ Your in-game loadout has been successfully updated!", ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to update loadout. Please check your token and file format.", ephemeral=True)

@tree.command(name="get_my_stash", description="Retrieves your own in-game stash as a JSON file.")
async def get_my_stash(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    user_id = interaction.user.id
    if user_id not in user_session_data or is_jwt_expired(user_session_data[user_id]["auth_token"]):
        await interaction.followup.send("❌ Your session has expired or you are not authenticated. Please run /acplayer first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    nakama_user_id = user_session_data[user_id]["nakama_user_id"]

    stash_data = await get_nakama_storage_data_for_user_id(auth_token, nakama_user_id, "stash")

    if stash_data:
        file_content = json.dumps(stash_data, indent=2)
        buffer = BytesIO(file_content.encode('utf-8'))
        file = discord.File(buffer, filename="your_stash.json")
        await interaction.followup.send("✅ Here is your current in-game stash:", file=file, ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to retrieve stash data. It might be empty or your token is invalid.", ephemeral=True)

@tree.command(name="add-item-to-stash", description="Upload a JSON file to add a new item or items to your stash.")
@app_commands.describe(item_file="A JSON file containing the item(s) to add to your stash.")
async def add_item_to_stash(interaction: discord.Interaction, item_file: discord.Attachment):
    await interaction.response.defer(ephemeral=True)

    user_id = interaction.user.id
    if user_id not in user_session_data or is_jwt_expired(user_session_data[user_id]["auth_token"]):
        await interaction.followup.send("❌ Your session has expired or you are not authenticated. Please run /acplayer first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    nakama_user_id = user_session_data[user_id]["nakama_user_id"]

    try:
        item_data = await item_file.read()
        items_to_add = json.loads(item_data)

        if not isinstance(items_to_add, list):
            items_to_add = [items_to_add]

    except Exception as e:
        await interaction.followup.send(f"❌ Failed to read or parse the JSON file: {e}", ephemeral=True)
        return

    current_stash = await get_nakama_storage_data_for_user_id(auth_token, nakama_user_id, "stash")
    if not current_stash or "items" not in current_stash:
        current_stash = {"items": []}

    used_positions = {item["stashPos"] for item in current_stash["items"]}

    for item in items_to_add:
        found_pos = None
        for row in range(8):
            for col in range(8):
                pos = row * 100 + col
                if pos not in used_positions:
                    found_pos = pos
                    used_positions.add(pos)
                    break
        
        if found_pos is not None:
            item["stashPos"] = found_pos
            current_stash["items"].append(item)
        else:
            await interaction.followup.send("❌ Failed to add all items: Your stash appears to be full.", ephemeral=True)
            return

    if await put_nakama_storage_data(auth_token, "stash", current_stash):
        await interaction.followup.send(f"✅ Successfully added {len(items_to_add)} item(s) to your stash!", ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to update your stash. The token may be expired or the file format is incorrect.", ephemeral=True)

@tree.command(name="nutbalance", description="Check your in-game currency balances.")
async def nutbalance(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=False)

    user_id = interaction.user.id
    if user_id not in user_session_data:
        await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]

    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token
            save_session_data()
        else:
            await interaction.followup.send("❌ Your session has expired and could not be refreshed. Please run `/acplayer` again to re-authenticate.", ephemeral=True)
            del user_session_data[user_id]
            save_session_data()
            return

    wallet_data = await get_nakama_wallet_data(auth_token)
    mining_data = await get_nakama_mining_balance(auth_token)

    if wallet_data is None and mining_data is None:
        await interaction.followup.send("❌ Failed to retrieve your currency balances. Your token might be invalid or the game server is unreachable.", ephemeral=True)
        return

    response_message = "**Your Currency Balances:**\n\n"

    nuts_wallet = wallet_data.get("softCurrency", 0) if wallet_data else 0
    cc_wallet = wallet_data.get("hardCurrency", 0) if wallet_data else 0
    rp_wallet = wallet_data.get("researchPoints", 0) if wallet_data else 0

    response_message += f"🌰 **NUTS (Wallet):** {nuts_wallet:,}\n"
    response_message += f"💰 **Company Coins (Wallet):** {cc_wallet:,}\n"
    response_message += f"🧪 **Research Points (Wallet):** {rp_wallet:,}\n\n"

    nuts_mining = "No Limit"
    cc_mining = mining_data.get("hardCurrency", 0) if mining_data else 0
    rp_mining = mining_data.get("researchPoints", 0) if mining_data else 0

    response_message += "**Mining Balances:**\n"
    response_message += f"⛏️ **NUTS (Mining):** {nuts_mining}\n"
    response_message += f"⛏️ **Company Coins (Mining):** {cc_mining:,}\n"
    response_message += f"⛏️ **Research Points (Mining):** {rp_mining:,}\n"
    await interaction.followup.send(response_message)

@tree.command(name="change_gorilla_color", description="Change your gorilla's body color to a new hex value.")
@app_commands.describe(hex_color="The new color as a 6-digit hex value (e.g., FF0000).")
async def change_gorilla_color(interaction: discord.Interaction, hex_color: str):
    await interaction.response.defer(ephemeral=True)
    user_id = interaction.user.id
    if user_id not in user_session_data:
        await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
        return
    hex_color = hex_color.lstrip('#')
    if not re.match(r'^[0-9a-fA-F]{6}$', hex_color):
        await interaction.followup.send("❌ Invalid hex color format. Please provide a 6-digit hex code like `FF0000`.", ephemeral=True)
        return
    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]
    nakama_user_id = user_session_data[user_id]["nakama_user_id"]
    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token
            save_session_data()
        else:
            await interaction.followup.send("❌ Your session has expired and could not be refreshed. Please run `/acplayer` again to re-authenticate.", ephemeral=True)
            del user_session_data[user_id]
            save_session_data()
            return
    loadout_data = await get_nakama_storage_data_for_user_id(auth_token, nakama_user_id, "gameplay_loadout")
    if not loadout_data:
        loadout_data = {
            "cosmetics": {},
            "equipments": {},
            "version": 0
        }
    if "cosmetics" not in loadout_data:
        loadout_data["cosmetics"] = {}
    loadout_data["cosmetics"]["body_skin"] = hex_color.upper()
    if await put_nakama_storage_data(auth_token, "gameplay_loadout", loadout_data):
        await interaction.followup.send(f"✅ Your gorilla's body color has been changed to **#{hex_color.upper()}**!", ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to update your loadout. Please check your token and try again.", ephemeral=True)

@tree.command(name="wipe_account_data", description="⚠️ Wipe some of your Animal Company data: stash, loadout. Wallet requires in-game action.")
async def wipe_account_data(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    user_id = interaction.user.id
    if user_id not in user_session_data:
        return await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
    view = ConfirmWipeView(user_id)
    await interaction.followup.send(
        "⚠️ This will attempt to wipe your **stash** and **loadout** data.\n"
        "**❗ Your wallet balance (Nuts, Company Coins, Research Points) CANNOT be reset by this bot.** "
        "This usually requires an in-game action or a specific server-side function.\n"
        "Are you sure you want to proceed with wiping stash and loadout?",
        view=view,
    )
    await view.wait()
    if view.result is None:
        return await interaction.followup.send("⌛ Timed out. Account wipe cancelled.", ephemeral=True)
    if not view.result:
        return

    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]

    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token
            save_session_data()
        else:
            del user_session_data[user_id]
            save_session_data()
            return await interaction.followup.send("❌ Token expired and could not be refreshed. Please re-authenticate with `/acplayer`.", ephemeral=True)

    wipe_results = []
    if await delete_nakama_storage_data(auth_token, "user_inventory", "stash"):
        wipe_results.append("✅ Stash wiped.")
    else:
        wipe_results.append("❌ Failed to wipe stash (it might already be empty or token issues).")

    if await delete_nakama_storage_data(auth_token, "user_inventory", "gameplay_loadout"):
        wipe_results.append("✅ Loadout wiped.")
    else:
        wipe_results.append("❌ Failed to wipe loadout (it might already be empty or token issues).")

    wipe_results.append("\n**❗ Wallet balance (Nuts, Company Coins, Research Points) was NOT reset.** This typically requires an in-game action or a specific server-side function to modify.")
    await interaction.followup.send("\n".join(wipe_results), ephemeral=True)

@tree.command(name="get_player_stash", description="Retrieves a player's stash using their Nakama user ID.")
@app_commands.describe(nakama_user_id="The unique Nakama user ID of the player.")
async def get_player_stash(interaction: discord.Interaction, nakama_user_id: str):
    await interaction.response.defer(ephemeral=True)

    user_id = interaction.user.id
    if user_id not in user_session_data:
        await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    
    stash_data = await get_nakama_storage_data_for_user_id(auth_token, nakama_user_id, "stash")

    if stash_data:
        file_content = json.dumps(stash_data, indent=2)
        buffer = BytesIO(file_content.encode('utf-8'))
        file = discord.File(buffer, filename=f"{nakama_user_id}_stash.json")
        await interaction.followup.send(f"✅ Here is the stash for user `{nakama_user_id}`:", file=file, ephemeral=True)
    else:
        await interaction.followup.send(f"❌ Failed to retrieve stash data for user `{nakama_user_id}`. It might be empty or your token is invalid.", ephemeral=True)

# New Command: get_individual_stash_items
@tree.command(name="get_individual_stash_items", description="Retrieves each individual item from your stash as a separate JSON file.")
@app_commands.describe(send_to_channel="Set to True to send the files in the current channel instead of your DMs.")
async def get_individual_stash_items(interaction: discord.Interaction, send_to_channel: Optional[bool] = False):
    """
    This command fetches a user's entire stash, then iterates through each item,
    sending a separate JSON file for each one.
    """
    await interaction.response.defer(ephemeral=not send_to_channel)

    user_id = interaction.user.id
    if user_id not in user_session_data:
        await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    nakama_user_id = user_session_data[user_id]["nakama_user_id"]

    # Retrieve the full stash data
    stash_data = await get_nakama_storage_data_for_user_id(auth_token, nakama_user_id, "stash")

    if not stash_data or not stash_data.get("items"):
        await interaction.followup.send("❌ Failed to retrieve stash data or your stash is empty.", ephemeral=True)
        return

    items = stash_data["items"]
    
    # Determine the destination for the files
    destination = interaction.channel if send_to_channel else await interaction.user.create_dm()

    # Send an initial message to the user
    if send_to_channel:
        await interaction.followup.send(
            f"✅ I am sending {len(items)} items from your stash in this channel now.",
        )
    else:
        await interaction.followup.send(
            f"✅ I am sending {len(items)} items from your stash to your DMs now. Please check your DMs.",
        )

    # Iterate through each item and send it as a separate file
    for i, item in enumerate(items, 1):
        try:
            item_id = item.get("id", f"unknown-item-{i}")
            file_content = json.dumps(item, indent=2)
            buffer = BytesIO(file_content.encode('utf-8'))
            file = discord.File(buffer, filename=f"item_{i}_{item_id}.json")
            await destination.send(f"Stash Item {i}/{len(items)}:", file=file)
            await asyncio.sleep(1) # Add a small delay to avoid rate-limiting
        except Exception as e:
            print(f"Error sending stash item {i}: {e}")
            await destination.send(f"❌ Failed to send item {i} due to an error.")

# End of new command

@tasks.loop(minutes=5)
async def track_player_status():
    if not tracked_players:
        track_player_status.cancel()
        return

    for player_identifier, tracking_info in list(tracked_players.items()):
        try:
            tracker_user = bot.get_user(tracking_info["tracker_id"])
            if not tracker_user:
                del tracked_players[player_identifier]
                continue
            
            dm_channel = tracker_user.dm_channel
            if not dm_channel:
                dm_channel = await tracker_user.create_dm()

            auth_token = user_session_data[tracking_info["tracker_id"]]["auth_token"]
            
            target_user = await get_user_data(auth_token, tracking_info["user_id"])

            if not target_user:
                await dm_channel.send(f"❌ Tracking stopped for `{tracking_info['username']}`: User not found.")
                del tracked_players[player_identifier]
                continue
            
            current_status = "Online" if target_user.get("online", False) else "Offline"

            if current_status != tracking_info["status"]:
                tracking_info["status"] = current_status
                now = datetime.now(timezone.utc)
                tracking_info["last_seen"] = now.isoformat()
                
                status_message = (
                    f"**🔔 Status Update**\n"
                    f"Player: `{tracking_info['username']}`\n"
                    f"New Status: `{'Online' if target_user.get('online', False) else 'Offline'}`\n"
                    f"Time: <t:{int(now.timestamp())}:F>"
                )
                await dm_channel.send(status_message)

        except Exception as e:
            print(f"Error during player status check for {player_identifier}: {e}")
            traceback.print_exc()

@tasks.loop(minutes=5)
async def claim_rewards_loop():
    if not autoclaim_users:
        claim_rewards_loop.cancel()
        return
        
    for user_id in list(autoclaim_users):
        try:
            user = bot.get_user(user_id)
            if not user:
                autoclaim_users.discard(user_id)
                save_session_data()
                continue
            
            if user_id not in user_session_data:
                autoclaim_users.discard(user_id)
                save_session_data()
                await user.send("❌ Your session has expired. Auto-claim has been disabled. Please run `/acplayer` to re-authenticate.")
                continue

            auth_token = user_session_data[user_id]["auth_token"]
            refresh_token_val = user_session_data[user_id]["refresh_token"]

            if is_jwt_expired(auth_token):
                new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
                if new_auth_token and new_refresh_token:
                    user_session_data[user_id]["auth_token"] = new_auth_token
                    user_session_data[user_id]["refresh_token"] = new_refresh_token
                    auth_token = new_auth_token
                    save_session_data()
                else:
                    autoclaim_users.discard(user_id)
                    del user_session_data[user_id]
                    save_session_data()
                    await user.send("❌ Your session has expired and could not be refreshed. Auto-claim has been disabled. Please run `/acplayer` to re-authenticate.")
                    continue

            claimed_rewards = await claim_mining_rewards(auth_token)

            if claimed_rewards:
                message = "**✅ Successfully claimed mining rewards!**\n\n"
                
                nuts_claimed = claimed_rewards.get("softCurrency", 0)
                cc_claimed = claimed_rewards.get("hardCurrency", 0)
                rp_claimed = claimed_rewards.get("researchPoints", 0)

                if nuts_claimed > 0:
                    message += f"🌰 **NUTS:** {nuts_claimed:,}\n"
                if cc_claimed > 0:
                    message += f"💰 **Company Coins:** {cc_claimed:,}\n"
                if rp_claimed > 0:
                    message += f"🧪 **Research Points:** {rp_claimed:,}\n"

                if nuts_claimed == 0 and cc_claimed == 0 and rp_claimed == 0:
                    message = "⚠️ There were no rewards to claim this time."
                
                try:
                    dm_channel = user.dm_channel
                    if not dm_channel:
                        dm_channel = await user.create_dm()
                    await dm_channel.send(message)
                except discord.Forbidden:
                    print(f"Could not DM user {user.id}. They may have DMs disabled.")

        except Exception as e:
            print(f"Error during reward claim for user {user_id}: {e}")
            traceback.print_exc()
            
@tree.command(name="auto-claim-mining", description="Toggles automatic claiming of mining rewards every 5 minutes.")
async def auto_claim_mining(interaction: discord.Interaction):
    user_id = interaction.user.id
    if user_id not in user_session_data:
        return await interaction.response.send_message("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)

    if user_id in autoclaim_users:
        autoclaim_users.discard(user_id)
        if not autoclaim_users and claim_rewards_loop.is_running():
            claim_rewards_loop.stop()
        save_session_data()
        await interaction.response.send_message("❌ Automatic mining reward claiming is now **disabled**.", ephemeral=True)
    else:
        autoclaim_users.add(user_id)
        if not claim_rewards_loop.is_running():
            claim_rewards_loop.start()
        save_session_data()
        await interaction.response.send_message("✅ Automatic mining reward claiming is now **enabled**! I will send you a DM every time I claim them.", ephemeral=True)


if __name__ == "__main__":
    bot.run(TOKEN)
