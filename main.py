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
# It's recommended to use a configuration file or environment variables for the token.
TOKEN = os.getenv("DISCORD_BOT_TOKEN")
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)
tree = bot.tree

# --- Session Data Persistence ---
SESSION_FILE = "session.json"

def load_session_data():
    """Loads session data from a JSON file, creating it if it doesn't exist."""
    if os.path.exists(SESSION_FILE):
        with open(SESSION_FILE, 'r') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print("WARNING: session.json file is corrupt, starting with an empty session.")
                return {}
    return {}

def save_session_data():
    """Saves the current session data to the JSON file."""
    with open(SESSION_FILE, 'w') as f:
        json.dump(user_session_data, f, indent=4)

# Centralized storage for user-specific data (token, user_id, etc.)
user_session_data = load_session_data()
print(f"DEBUG: Loaded session data on startup: {user_session_data}")

# --- Caches and Storage ---
metadata_cache = {}

# --- Helper Functions ---
def extract_strings(data: bytes):
    """Extracts printable ASCII strings from binary data."""
    pattern = re.compile(rb'[\x20-\x7E]{4,}')
    strings, offsets = [], []
    for m in pattern.finditer(data):
        offsets.append(m.start())
        strings.append(m.group().decode("utf-8", errors="ignore"))
    return strings, offsets

async def fetch_pixeldrain_file(key: str):
    """Fetches a file from Pixeldrain using its key."""
    url = f"https://pixeldrain.com/api/file/{key}"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            if resp.status != 200:
                return None, resp.status
            return await resp.read(), 200

def extract_tokens_from_data_url(xmod_url: str):
    """Extracts tokens from a URL's 'data' query parameter."""
    try:
        query = urlparse(xmod_url).query
        params = parse_qs(query)
        if "data" not in params:
            return None, None, None
        decoded = unquote(params["data"][0])
        data_array = json.loads(decoded)
        if isinstance(data_array, list) and len(data_array) >= 3:
            return data_array[0], data_array[1], data_array[2] # username, auth_token, refresh_token
    except (json.JSONDecodeError, IndexError, KeyError):
        return None, None, None
    return None, None, None

def is_jwt_expired(token: str) -> bool:
    """Checks if a JWT token is expired."""
    try:
        payload_b64 = token.split('.')[1]
        payload_b64 += '=' * (-len(payload_b64) % 4) # Pad if necessary
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp")
        return exp is not None and int(time.time()) >= exp
    except Exception as e:
        print(f"DEBUG: JWT expiration check failed: {e}")
        return True # Assume expired if invalid

async def refresh_token(refresh_token_str: str) -> tuple[str | None, str | None]:
    """Uses a refresh token to get a new auth and refresh token."""
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account/session/refresh"
    # This is a hardcoded Nakama API key, specific to the client.
    headers = {"Authorization": "Basic NlVSdVRTbERLS2ZZYnVEVzo="}
    data = {"token": refresh_token_str}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=data) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                return response_data.get("token"), response_data.get("refresh_token")
            else:
                print(f"DEBUG: Token refresh failed. Status: {resp.status}, Response: {await resp.text()}")
                return None, None

async def get_user_id(auth_token: str) -> str | None:
    """Fetches the user_id associated with an auth token."""
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account"
    headers = {"Authorization": f"Bearer {auth_token}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                return response_data.get("user", {}).get("id")
            return None

async def get_nakama_storage_data(auth_token: str, user_id: str, key: str) -> dict | None:
    """Fetches a specific storage object from Nakama."""
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/storage"
    headers = {"Authorization": f"Bearer {auth_token}"}
    body = {"object_ids": [{"collection": "user_inventory", "key": key, "user_id": user_id}]}
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=body) as resp:
            if resp.status == 200:
                data = await resp.json()
                objects = data.get("objects", [])
                if objects and "value" in objects[0]:
                    return json.loads(objects[0]["value"])
            return None

async def put_nakama_storage_data(auth_token: str, key: str, value: dict) -> bool:
    """Writes a storage object to Nakama."""
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/storage"
    headers = {"Authorization": f"Bearer {auth_token}"}
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
            return resp.status == 204

async def delete_nakama_storage_data(auth_token: str, key: str) -> bool:
    """Deletes a storage object from Nakama."""
    collection = "user_inventory"
    url = f"https://animalcompany.us-east1.nakamacloud.io/v2/storage?collection={collection}&key={key}"
    headers = {"Authorization": f"Bearer {auth_token}"}
    async with aiohttp.ClientSession() as session:
        async with session.delete(url, headers=headers) as resp:
            return resp.status == 204

async def get_nakama_wallet_data(auth_token: str) -> dict | None:
    """Fetches the user's wallet data from Nakama."""
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account"
    headers = {"Authorization": f"Bearer {auth_token}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                if "wallet" in response_data:
                    return json.loads(response_data["wallet"])
            return None

async def update_nakama_wallet(auth_token: str, new_wallet_data: dict) -> bool:
    """Updates the user's wallet data on Nakama."""
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/account/wallet"
    headers = {"Authorization": f"Bearer {auth_token}"}
    # Nakama requires a 'changeset' for wallet updates.
    body = {"changeset": new_wallet_data}
    async with aiohttp.ClientSession() as session:
        async with session.put(url, headers=headers, json=body) as resp:
            return resp.status == 204

async def get_nakama_mining_balance(auth_token: str) -> dict | None:
    """Fetches the user's mining balance from a Nakama RPC."""
    url = "https://animalcompany.us-east1.nakamacloud.io/v2/rpc/mining.balance"
    headers = {"Authorization": f"Bearer {auth_token}"}
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers) as resp:
            if resp.status == 200:
                response_data = await resp.json()
                if "payload" in response_data:
                    return json.loads(response_data["payload"])
            return None

# A helper to manage authentication and token refreshing for commands
async def authenticated_api_call(interaction: discord.Interaction):
    """
    Checks for user authentication and handles token refreshing.
    Returns the valid auth_token or None if authentication fails.
    """
    user_id = str(interaction.user.id)
    if user_id not in user_session_data:
        await interaction.followup.send("❌ You are not authenticated. Please run `/acplayer` first.", ephemeral=True)
        return None

    auth_token = user_session_data[user_id]["auth_token"]
    refresh_token_val = user_session_data[user_id]["refresh_token"]

    if is_jwt_expired(auth_token):
        print(f"DEBUG: Token expired for user {user_id}. Attempting refresh.")
        new_auth, new_refresh = await refresh_token(refresh_token_val)
        if new_auth and new_refresh:
            user_session_data[user_id]["auth_token"] = new_auth
            user_session_data[user_id]["refresh_token"] = new_refresh
            save_session_data()
            print(f"DEBUG: Token successfully refreshed for user {user_id}.")
            return new_auth
        else:
            await interaction.followup.send("❌ Your session has expired and could not be refreshed. Please run `/acplayer` again.", ephemeral=True)
            del user_session_data[user_id]
            save_session_data()
            return None
    
    return auth_token

# --- UI Views ---
class ConfirmWipeView(View):
    def __init__(self, user_id):
        super().__init__(timeout=60)
        self.user_id = user_id
        self.result = None

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        return interaction.user.id == self.user_id

    @discord.ui.button(label="Confirm Wipe", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: Button):
        self.result = True
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(content="Wiping data...", view=self)
        self.stop()

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: Button):
        self.result = False
        for item in self.children:
            item.disabled = True
        await interaction.response.edit_message(content="Account wipe cancelled.", view=self)
        self.stop()

# --- Discord Commands ---
@tree.command(name="acplayer", description="Authenticate with the game via an xmod URL.")
@app_commands.describe(xmod_url="The URL from the ACTools API page (Copy ShareURL).")
async def acplayer(interaction: discord.Interaction, xmod_url: str):
    await interaction.response.defer(ephemeral=True)
    username, auth_token, refresh_token = extract_tokens_from_data_url(xmod_url)

    if not auth_token or not refresh_token:
        await interaction.followup.send("❌ Invalid xmod URL format. Please provide the full URL.", ephemeral=True)
        return

    nakama_user_id = await get_user_id(auth_token)
    if not nakama_user_id:
        await interaction.followup.send("❌ Failed to verify token. It may be expired or invalid. Please generate a new URL.", ephemeral=True)
        return

    # Store user data using their Discord ID as the key
    user_session_data[str(interaction.user.id)] = {
        "auth_token": auth_token,
        "refresh_token": refresh_token,
        "nakama_user_id": nakama_user_id
    }
    save_session_data()
    await interaction.followup.send(f"✅ Successfully authenticated as **{username}**! Your session is saved.", ephemeral=True)


@tree.command(name="add-item-to-stash", description="Adds an item from a JSON file to your stash.")
@app_commands.describe(item_file="A JSON file containing the item(s) to add.")
async def add_item_to_stash(interaction: discord.Interaction, item_file: discord.Attachment):
    # FIX: Added defer() to prevent the interaction from timing out during API calls.
    await interaction.response.defer(ephemeral=True)
    auth_token = await authenticated_api_call(interaction)
    if not auth_token:
        return

    try:
        item_data_bytes = await item_file.read()
        items_to_add = json.loads(item_data_bytes)
        if not isinstance(items_to_add, list):
            items_to_add = [items_to_add]
    except (json.JSONDecodeError, TypeError):
        await interaction.followup.send("❌ Invalid JSON file. Please check the file content and format.", ephemeral=True)
        return

    user_id = str(interaction.user.id)
    nakama_user_id = user_session_data[user_id]["nakama_user_id"]
    
    current_stash = await get_nakama_storage_data(auth_token, nakama_user_id, "stash")
    if not current_stash or "items" not in current_stash:
        current_stash = {"items": []}

    used_positions = {item.get("stashPos", -1) for item in current_stash["items"]}
    
    # Add new items to the stash, finding the first available position
    for item in items_to_add:
        # Find the first available position in an 8x8 grid.
        found_pos = -1
        for pos in range(8 * 100): # Simplified loop
            if (pos % 100) < 8 and pos not in used_positions:
                found_pos = pos
                break
        
        if found_pos == -1:
            await interaction.followup.send("❌ Failed to add item: Your stash is full.", ephemeral=True)
            return # Stop if one item fails to find a spot

        item["stashPos"] = found_pos
        current_stash["items"].append(item)
        used_positions.add(found_pos)

    if await put_nakama_storage_data(auth_token, "stash", current_stash):
        await interaction.followup.send(f"✅ Successfully added {len(items_to_add)} item(s) to your stash!", ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to update your stash on the server.", ephemeral=True)


@tree.command(name="addacfriend", description="Sends a friend request to a user in Animal Company.")
@app_commands.describe(username="The in-game username of the person to add.")
async def addacfriend(interaction: discord.Interaction, username: str):
    await interaction.response.defer(ephemeral=True)
    auth_token = await authenticated_api_call(interaction)
    if not auth_token:
        return
        
    url = f"https://animalcompany.us-east1.nakamacloud.io/v2/friend?usernames={username}"
    headers = {"Authorization": f"Bearer {auth_token}"}

    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers) as resp:
            # FIX: The Nakama API has specific status codes for this action.
            # 204 means the request was successfully sent.
            if resp.status == 204:
                await interaction.followup.send(f"✅ Friend request sent to `{username}`!", ephemeral=True)
            # 200 means the request was processed but no action was taken (e.g., user not found, already friends).
            elif resp.status == 200:
                await interaction.followup.send(f"⚠️ Could not send request. The user `{username}` may not exist or you are already friends.", ephemeral=True)
            else:
                error_text = await resp.text()
                await interaction.followup.send(f"❌ An error occurred. Status: `{resp.status}`\n`{error_text}`", ephemeral=True)

@tree.command(name="nutbalance", description="Check your in-game currency balances.")
async def nutbalance(interaction: discord.Interaction):
    # FIX: Changed defer to ephemeral for user privacy.
    await interaction.response.defer(ephemeral=True)
    auth_token = await authenticated_api_call(interaction)
    if not auth_token:
        return

    wallet_data = await get_nakama_wallet_data(auth_token)
    mining_data = await get_nakama_mining_balance(auth_token)

    if wallet_data is None and mining_data is None:
        await interaction.followup.send("❌ Failed to retrieve balances. Your token may be invalid.", ephemeral=True)
        return

    embed = discord.Embed(title="Your Currency Balances", color=discord.Color.gold())
    
    # Wallet Balances
    nuts_wallet = wallet_data.get("softCurrency", 0) if wallet_data else 0
    cc_wallet = wallet_data.get("hardCurrency", 0) if wallet_data else 0
    rp_wallet = wallet_data.get("researchPoints", 0) if wallet_data else 0

    embed.add_field(name="🌰 NUTS (Wallet)", value=f"{nuts_wallet:,}", inline=True)
    embed.add_field(name="💰 Company Coins (Wallet)", value=f"{cc_wallet:,}", inline=True)
    embed.add_field(name="🧪 Research Points (Wallet)", value=f"{rp_wallet:,}", inline=True)
    
    # Mining Balances
    embed.add_field(name="\u200b", value="\u200b", inline=False) # Spacer
    cc_mining = mining_data.get("hardCurrency", 0) if mining_data else 0
    rp_mining = mining_data.get("researchPoints", 0) if mining_data else 0

    embed.add_field(name="⛏️ NUTS (Mining)", value="No Limit", inline=True)
    embed.add_field(name="⛏️ Company Coins (Mining)", value=f"{cc_mining:,}", inline=True)
    embed.add_field(name="⛏️ Research Points (Mining)", value=f"{rp_mining:,}", inline=True)

    await interaction.followup.send(embed=embed, ephemeral=True)


@tree.command(name="getnutstocap", description="Sets your NUTS balance to the maximum of 9,990,000.")
async def getnutstocap(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    auth_token = await authenticated_api_call(interaction)
    if not auth_token:
        return

    # FIX: Safely update wallet by preserving other currency values.
    current_wallet = await get_nakama_wallet_data(auth_token)
    if current_wallet is None:
        await interaction.followup.send("❌ Failed to retrieve your current wallet to perform the update.", ephemeral=True)
        return
        
    # Prepare the changeset for the API
    new_wallet_changes = {
        "softCurrency": 9990000,
        "hardCurrency": current_wallet.get("hardCurrency", 0),
        "researchPoints": current_wallet.get("researchPoints", 0)
    }

    if await update_nakama_wallet(auth_token, new_wallet_changes):
        await interaction.followup.send("✅ Your NUTS balance has been set to **9,990,000**! You may need to restart the game.", ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to update your NUTS balance.", ephemeral=True)


@tree.command(name="change_gorilla_color", description="Change your gorilla's body color.")
@app_commands.describe(hex_color="The new color as a 6-digit hex value (e.g., FF0000).")
async def change_gorilla_color(interaction: discord.Interaction, hex_color: str):
    await interaction.response.defer(ephemeral=True)
    
    hex_color = hex_color.lstrip('#')
    if not re.match(r'^[0-9a-fA-F]{6}$', hex_color):
        await interaction.followup.send("❌ Invalid hex color. Please use a 6-digit format like `FF0000`.", ephemeral=True)
        return

    auth_token = await authenticated_api_call(interaction)
    if not auth_token:
        return

    user_id = str(interaction.user.id)
    nakama_user_id = user_session_data[user_id]["nakama_user_id"]

    # FIX: Safely get the loadout, or create a default one.
    loadout_data = await get_nakama_storage_data(auth_token, nakama_user_id, "gameplay_loadout")
    if loadout_data is None:
        loadout_data = {"cosmetics": {}, "equipments": {}, "version": 0}
        
    if "cosmetics" not in loadout_data:
        loadout_data["cosmetics"] = {}

    loadout_data["cosmetics"]["body_skin"] = hex_color.upper()

    if await put_nakama_storage_data(auth_token, "gameplay_loadout", loadout_data):
        await interaction.followup.send(f"✅ Gorilla color changed to **#{hex_color.upper()}**!", ephemeral=True)
    else:
        await interaction.followup.send("❌ Failed to update your loadout.", ephemeral=True)

@tree.command(name="wipe_account_data", description="⚠️ Wipes your stash and loadout data.")
async def wipe_account_data(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    
    view = ConfirmWipeView(interaction.user.id)
    await interaction.followup.send(
        "⚠️ This will permanently delete your **stash** and **loadout**.\n"
        "This action cannot be undone. Are you sure?",
        view=view,
        ephemeral=True
    )
    await view.wait()

    if view.result is not True:
        # Message is handled by the view for cancellation or timeout
        if view.result is None:
            await interaction.edit_original_response(content="⌛ Wipe cancelled due to timeout.", view=None)
        return

    auth_token = await authenticated_api_call(interaction)
    if not auth_token:
        return

    results = []
    if await delete_nakama_storage_data(auth_token, "stash"):
        results.append("✅ Stash wiped successfully.")
    else:
        results.append("❌ Failed to wipe stash (it may have already been empty).")

    if await delete_nakama_storage_data(auth_token, "gameplay_loadout"):
        results.append("✅ Loadout wiped successfully.")
    else:
        results.append("❌ Failed to wipe loadout (it may have already been empty).")

    results.append("\n**Note:** Wallet balances (Nuts, etc.) are not affected.")
    await interaction.edit_original_response(content="\n".join(results), view=None)


# --- Bot Events and Startup ---
@bot.event
async def on_ready():
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")
    try:
        synced_commands = await tree.sync()
        print(f"Synced {len(synced_commands)} global commands.")
    except Exception as e:
        print(f"ERROR: Command sync failed: {e}")

if __name__ == "__main__":
    if TOKEN:
        bot.run(TOKEN)
    else:
        print("ERROR: DISCORD_BOT_TOKEN environment variable not set.")

```
