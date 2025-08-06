import discord
from discord import app_commands
from discord.ext import commands
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
from typing import Optional

# --- Setup ---
TOKEN = os.getenv("DISCORD_BOT_TOKEN")  # Set this in your Replit secrets
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

# --- Session Data Persistence ---
SESSION_FILE = "session.json"

def load_session_data():
    """Loads session data from a JSON file."""
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print("WARNING: session.json file is corrupt, starting with an empty session.")
                return {}
    return {}

def save_session_data():
    """Saves session data to a JSON file."""
    with open(SESSION_FILE, 'w') as f:
        json.dump(user_session_data, f)

# Centralized storage for user-specific data (token, user_id, etc.)
user_session_data = load_session_data()
print(f"DEBUG: Loaded session data on startup: {user_session_data}")

# --- Caches and Storage ---
metadata_cache = {}

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
            return False # No expiration claim
        now = int(time.time())
        return now >= exp
    except Exception as e:
        print(f"DEBUG: JWT expiration check failed: {e}")
        return True # Assume invalid or expired if decoding fails

async def refresh_token(refresh_token: str) -> tuple[str | None, str | None]:
    """
    Uses the refresh token to get a new auth and refresh token.
    Returns (new_auth_token, new_refresh_token) or (None, None).
    """
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account/session/refresh"
    headers = {
        "Authorization": "Basic NlVSdVRTbERLS2ZZYnVEVzo=", # This is a hardcoded Nakama API key
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

async def get_nakama_storage_data(auth_token: str, user_id: str, key: str) -> dict | None:
    """
    Fetches data from a user's Nakama storage.
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
    # The API for deleting storage objects uses query parameters, not a JSON body
    url = f"https://animalcompany.us-east1.nakamacloud.io/v2/storage?collection={collection}&key={key}"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json"
    }

    async with aiohttp.ClientSession() as session:
        async with session.delete(url, headers=headers) as resp:
            if resp.status == 204: # 204 No Content is the successful response for DELETE
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
    # Nakama requires a changeset for wallet updates
    body = {"changeset": {"set": new_wallet_data}}

    async with aiohttp.ClientSession() as session:
        async with session.put(url, headers=headers, json=body) as resp:
            if resp.status == 204: # 204 No Content is a successful response for wallet updates
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
        data = metadata_cache[self.user_id]
        if data["page"] > 0:
            data["page"] -= 1
            await update_metadata_message(inter, data, self.message)

    @discord.ui.button(label="⏭️ Next", style=discord.ButtonStyle.secondary)
    async def next(self, inter: discord.Interaction, btn: Button):
        data = metadata_cache[self.user_id]
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
    content = f"📄 **Page {page+1}**\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(slice_, 1))
    view = MetadataView(inter.user.id, message)
    await inter.response.edit_message(content=content, view=view)


class ConfirmWipeView(View):
    def __init__(self, user_id):
        super().__init__(timeout=60)
        self.user_id = user_id
        self.result = None  # True for Confirm, False for Cancel, None for timeout

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
    sent = await inter.response.send_message(content, view=view, ephemeral=True)
    view.message = await sent.original_response()

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
        ephemeral=False
    )
    view.bot_message = await inter.original_response()

@tree.command(name="scan_apk", description="Scan APK metadata from Pixeldrain")
@app_commands.describe(pixeldrain_url="Pixeldrain URL")
async def scan_apk(inter: discord.Interaction, pixeldrain_url: str):
    if "pixeldrain.com" not in pixeldrain_url:
        return await inter.followup.send("❌ Invalid Pixeldrain URL.")
    key = pixeldrain_url.rstrip("/").split("/")[-1]
    data, status = await fetch_pixeldrain_file(key)
    if not data:
        return await inter.followup.send(f"❌ Download failed: HTTP {status}")
    await inter.followup.send(f"📦 APK size: {len(data)} bytes.", ephemeral=True)

@tree.command(name="generate_nitro", description="Generate a fake Nitro code")
async def generate_nitro(inter: discord.Interaction):
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
    await interaction.response.defer(ephemeral=True) # Acknowledge the interaction immediately

    username, auth_token, refresh_token = extract_tokens_from_data_url(xmod_url)

    if not auth_token or not refresh_token:
        await interaction.followup.send("❌ Invalid xmod URL. Please provide the full URL from the ACTools API page.", ephemeral=True)
        return

    nakama_user_id = await get_user_id(auth_token)
    if not nakama_user_id:
        await interaction.followup.send("❌ Failed to get user ID with the provided token. The token may be expired or invalid. Please generate a new URL and try again.", ephemeral=True)
        return

    # Store the tokens and user ID in the session data
    user_session_data[interaction.user.id] = {
        "auth_token": auth_token,
        "refresh_token": refresh_token,
        "nakama_user_id": nakama_user_id
    }
    print(f"DEBUG: Successfully stored token for user {interaction.user.id}")

    # Save the updated session data to the file
    save_session_data()
    print(f"DEBUG: Saved session data to file.")

    await interaction.followup.send(f"✅ Successfully authenticated as **{username}**! Your auth_token and user_id are now saved. You can now use other commands like /editstash or /add-item-to-stash.", ephemeral=True)

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

    # API endpoint to update account details
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

    # Nakama storage key for loadout
    key = "gameplay_loadout"

    if await put_nakama_storage_data(auth_token, key, loadout_json):
        await interaction.followup.send("✅ Your in-game loadout has been successfully updated!", ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to update loadout. Please check your token and file format.", ephemeral=True)

@tree.command(name="editstash", description="Retrieves your in-game stash as a JSON file.")
async def editstash(interaction: discord.Interaction):
    user_id = interaction.user.id
    if user_id not in user_session_data or is_jwt_expired(user_session_data[user_id]["auth_token"]):
        await interaction.followup.send("❌ Your session has expired or you are not authenticated. Please run /acplayer first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    nakama_user_id = user_session_data[user_id]["nakama_user_id"]

    stash_data = await get_nakama_storage_data(auth_token, nakama_user_id, "stash")

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
    # This is the corrected version of the command with the defer call
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

        # Ensure the items to add are in a list format for easier processing
        if not isinstance(items_to_add, list):
            items_to_add = [items_to_add]

    except Exception as e:
        await interaction.followup.send(f"❌ Failed to read or parse the JSON file: {e}", ephemeral=True)
        return

    # Step 1: Get the current stash
    current_stash = await get_nakama_storage_data(auth_token, nakama_user_id, "stash")
    if not current_stash or "items" not in current_stash:
        # If no stash exists, create a new one
        current_stash = {"items": []}

    # Get all used positions from the current stash
    used_positions = {item["stashPos"] for item in current_stash["items"]}

    # Step 2: Add new items to the stash
    for item in items_to_add:
        found_pos = None
        # Max stash size from the original web API (8x8)
        for row in range(8):
            for col in range(8):
                pos = row * 100 + col
                if pos not in used_positions:
                    found_pos = pos
                    used_positions.add(pos)
                    break
            if found_pos is not None:
                break

        if found_pos is None:
            await interaction.followup.send("❌ Failed to add all items: Your stash appears to be full.", ephemeral=True)
            return

        item["stashPos"] = found_pos
        current_stash["items"].append(item)

    # Step 3: Save the updated stash back to the server
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

    # Attempt to refresh token if expired
    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token # Use the new token for subsequent requests
            # We cannot send another followup here as it might fail if the defer was not ephemeral.
            # The next followup will send the main message.
            save_session_data()
        else:
            await interaction.followup.send("❌ Your session has expired and could not be refreshed. Please run `/acplayer` again to re-authenticate.", ephemeral=True)
            # Clear expired tokens for this user
            del user_session_data[user_id]
            save_session_data() # Save the change
            return

    wallet_data = await get_nakama_wallet_data(auth_token)
    mining_data = await get_nakama_mining_balance(auth_token)

    if wallet_data is None and mining_data is None:
        await interaction.followup.send("❌ Failed to retrieve your currency balances. Your token might be invalid or the game server is unreachable.", ephemeral=True)
        return

    response_message = "**Your Currency Balances:**\n\n"

    # Wallet Balances
    nuts_wallet = wallet_data.get("softCurrency", 0) if wallet_data else 0
    cc_wallet = wallet_data.get("hardCurrency", 0) if wallet_data else 0
    rp_wallet = wallet_data.get("researchPoints", 0) if wallet_data else 0

    response_message += f"🌰 **NUTS (Wallet):** {nuts_wallet:,}\n"
    response_message += f"💰 **Company Coins (Wallet):** {cc_wallet:,}\n"
    response_message += f"🧪 **Research Points (Wallet):** {rp_wallet:,}\n\n"

    # Mining Balances
    nuts_mining = "No Limit" # Based on the JS, "NUTS" mining balance is "No Limit"
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

    # Remove optional '#' prefix and validate hex color format
    hex_color = hex_color.lstrip('#')
    if not re.match(r'^[0-9a-fA-F]{6}$', hex_color):
        await interaction.followup.send("❌ Invalid hex color format. Please provide a 6-digit hex code like `FF0000`.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]
    nakama_user_id = user_session_data[user_id]["nakama_user_id"]

    # Attempt to refresh token if expired
    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token
            save_session_data() # Save the updated tokens
        else:
            await interaction.followup.send("❌ Your session has expired and could not be refreshed. Please run `/acplayer` again to re-authenticate.", ephemeral=True)
            del user_session_data[user_id]
            save_session_data() # Save the change
            return

    # Get current loadout data
    loadout_data = await get_nakama_storage_data(auth_token, nakama_user_id, "gameplay_loadout")
    if not loadout_data:
        # If loadout doesn't exist, create a default one for the color change
        loadout_data = {
            "cosmetics": {},
            "equipments": {},
            "version": 0
        }
        await interaction.followup.send("ℹ️ Your loadout data was not found, creating a new one to apply the color change.", ephemeral=True)

    # Add defensive check for 'cosmetics' key
    if "cosmetics" not in loadout_data:
        loadout_data["cosmetics"] = {}

    # Update the body_skin cosmetic
    loadout_data["cosmetics"]["body_skin"] = hex_color.upper()

    # Save the updated loadout back to the server
    if await put_nakama_storage_data(auth_token, "gameplay_loadout", loadout_data):
        await interaction.followup.send(f"✅ Your gorilla's body color has been changed to **#{hex_color.upper()}**!", ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to update your loadout. Please check your token and try again.", ephemeral=True)

@tree.command(name="wipe_account_data", description="⚠️ Wipe some of your Animal Company data: stash, loadout. Wallet requires in-game action.")
async def wipe_account_data(interaction: discord.Interaction):
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
        return # Already handled by view

    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]
    # nakama_user_id is not strictly needed for DELETE operations on user's own storage

    # Refresh token if needed
    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token
            save_session_data() # Save the updated tokens
        else:
            del user_session_data[user_id]
            save_session_data() # Save the change
            return await interaction.followup.send("❌ Token expired and could not be refreshed. Please re-authenticate with `/acplayer`.", ephemeral=True)

    wipe_results = []

    # Attempt to delete stash
    if await delete_nakama_storage_data(auth_token, "user_inventory", "stash"):
        wipe_results.append("✅ Stash wiped.")
    else:
        wipe_results.append("❌ Failed to wipe stash (it might already be empty or token issues).")

    # Attempt to delete loadout
    if await delete_nakama_storage_data(auth_token, "user_inventory", "gameplay_loadout"):
        wipe_results.append("✅ Loadout wiped.")
    else:
        wipe_results.append("❌ Failed to wipe loadout (it might already be empty or token issues).")

    wipe_results.append("\n**❗ Wallet balance (Nuts, Company Coins, Research Points) was NOT reset.** This typically requires an in-game action or a specific server-side function to modify.")

    await interaction.followup.send("\n".join(wipe_results), ephemeral=True)

@tree.command(name="retrieve_friends_list", description="Retrieves your Animal Company friends list.")
async def retrieve_friends_list(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    user_id = interaction.user.id
    if user_id not in user_session_data:
        await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]

    # Attempt to refresh token if expired
    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token # Use the new token for subsequent requests
            # Not sending a followup message here, the main one will follow.
            save_session_data() # Save the updated tokens
        else:
            await interaction.followup.send("❌ Your session has expired and could not be refreshed. Please run `/acplayer` again to re-authenticate.", ephemeral=True)
            # Clear expired tokens for this user
            del user_session_data[user_id]
            save_session_data() # Save the change
            return

    url = "https://animalcompany.us-east1.nakamacloud.io/v2/friend?limit=100" # Added limit for more friends if needed
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json"
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                friends = response_data.get("friends", [])

                if not friends:
                    await interaction.followup.send("🫥 You don't have any friends in Animal Company yet.", ephemeral=True)
                    return

                friends_list_message = "**Your Animal Company Friends:**\n"
                for friend in friends:
                    user_info = friend.get("user", {})
                    username = user_info.get("username", "Unknown User")
                    friend_id = user_info.get("id", "N/A")
                    online = "🟢 Online" if friend.get("online", False) else "🔴 Offline"
                    friends_list_message += f"- **{username}** (ID: `{friend_id}`) - {online}\n"

                # If the message is too long for Discord (max 2000 characters), split it
                if len(friends_list_message) > 2000:
                    await interaction.followup.send("✅ Your friends list is quite long. Sending it in multiple messages...", ephemeral=True)
                    # Split and send
                    for i in range(0, len(friends_list_message), 1900): # Use 1900 to be safe
                        await interaction.followup.send(friends_list_message[i:i+1900], ephemeral=True)
                else:
                    await interaction.followup.send(friends_list_message, ephemeral=True)

            else:
                error_detail = await resp.text()
                print(f"DEBUG: Failed to retrieve friends list. Status: {resp.status}, Response: {error_detail}")
                await interaction.followup.send(f"❌ Failed to retrieve friends list. Status: `{resp.status}`. Your token might be invalid or expired. Try `/acplayer` again.", ephemeral=True)

@tree.command(name="addacfriend", description="Sends a friend request to a user in Animal Company.")
@app_commands.describe(username="The Animal Company username of the person to add.")
async def addacfriend(interaction: discord.Interaction, username: str):
    """
    Sends a friend request to a specified user using the Nakama API.
    """
    await interaction.response.defer(ephemeral=True)

    # 1. Retrieve the user's session data
    user_id = str(interaction.user.id)
    if user_id not in user_session_data:
        await interaction.followup.send(
            "❌ Please use the `/acplayer` command first to set up your session.",
        )
        return

    auth_token = user_session_data[user_id].get("auth_token")
    if not auth_token:
        await interaction.followup.send(
            "❌ Your authentication token is missing. Please re-run `/acplayer`.",
        )
        return

    # Add token refresh logic here
    refresh_token_val = user_session_data[user_id]["refresh_token"]
    if is_jwt_expired(auth_token):
        new_auth_token, new_refresh_token = await refresh_token(refresh_token_val)
        if new_auth_token and new_refresh_token:
            user_session_data[user_id]["auth_token"] = new_auth_token
            user_session_data[user_id]["refresh_token"] = new_refresh_token
            auth_token = new_auth_token
            save_session_data()
        else:
            await interaction.followup.send(
                "❌ Your session has expired and could not be refreshed. Please run `/acplayer` again to re-authenticate.",
                ephemeral=True
            )
            del user_session_data[user_id]
            save_session_data()
            return

    # 2. Construct the Nakama API request
    nakama_url = f"https://animalcompany.us-east1.nakamacloud.io/v2/friend?usernames={username}"
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }

    async with aiohttp.ClientSession() as session:
        try:
            # 3. Send the API request
            async with session.post(nakama_url, headers=headers) as resp:
                # 4. Handle the API response
                if resp.status == 204:
                    # The expected success code
                    await interaction.followup.send(
                        f"✅ Friend request sent to `{username}`!",
                    )
                elif resp.status == 200:
                    # The API returns 200 with an empty body when the friend request
                    # is not possible (e.g., already friends, user doesn't exist).
                    await interaction.followup.send(
                        f"⚠️ The user `{username}` was not found, or you are already friends.",
                        ephemeral=True
                    )
                else:
                    # A catch-all for any other unexpected status codes
                    error_message = await resp.text()
                    await interaction.followup.send(
                        f"❌ An unexpected error occurred. Status: `{resp.status}`. "
                        f"Error: `{error_message}`",
                    )
        except aiohttp.ClientError as e:
            await interaction.followup.send(
                f"❌ An error occurred while communicating with the server: `{e}`",
            )

@tree.command(name="getnutstocap", description="Changes your NUTS amount to the maximum of 9,990,000.")
async def getnutstocap(interaction: discord.Interaction):
    """
    Changes the user's NUTS currency to the capped amount.
    """

    await interaction.response.defer(ephemeral=True)

    user_id = interaction.user.id
    if user_id not in user_session_data:
        await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
        return

    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]

    # Attempt to refresh token if expired
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

    # Fetch current wallet data to preserve other currency amounts
    current_wallet_data = await get_nakama_wallet_data(auth_token)
    if not current_wallet_data:
        await interaction.followup.send("❌ Failed to retrieve your current wallet. Your token might be invalid or the game server is unreachable.", ephemeral=True)
        return

    # Prepare the new wallet data
    new_wallet_data = {
        "softCurrency": 9990000,
        "hardCurrency": current_wallet_data.get("hardCurrency", 0),
        "researchPoints": current_wallet_data.get("researchPoints", 0)
    }

    # Update the wallet
    if await update_nakama_wallet(auth_token, new_wallet_data):
        await interaction.followup.send(
            f"✅ Your NUTS amount has been successfully changed to **9,990,000**! "
            f"You may need to restart your game client to see the change."
        )
    else:
        await interaction.followup.send(
            "❌ Failed to update your NUTS amount. Please check your token and try again."
        )

# --- Bot Events and Startup ---
@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    try:
        # --- RECOMMENDED: GUILD-SPECIFIC SYNC FOR TESTING ---
        # Replace YOUR_GUILD_ID_HERE with the actual ID of your server
        # To get your guild ID, enable Developer Mode in Discord settings (Appearance -> Advanced),
        # then right-click your server's icon and choose "Copy ID".
        # test_guild_id = YOUR_GUILD_ID_HERE # <<< Uncomment and REPLACE THIS LINE
        # guild_object = discord.Object(id=test_guild_id)
        # synced_commands = await tree.sync(guild=guild_object)
        # print(f"DEBUG: Synced {len(synced_commands)} commands specifically to guild {test_guild_id}.")

        # --- GLOBAL SYNC (can take up to an hour to propagate) ---
        # Uncomment the two lines below and comment out the guild-specific sync above
        # once you are satisfied with testing.
        synced_commands = await tree.sync()
        print(f"DEBUG: Synced {len(synced_commands)} global commands.")

        for command in synced_commands:
            print(f"DEBUG: Synced command: /{command.name}")

    except Exception as e:
        print(f"ERROR: Command sync failed: {e}")

if __name__ == "__main__":
    bot.run(TOKEN)