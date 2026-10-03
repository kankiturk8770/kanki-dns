pub struct Preset {
    pub name: &'static str,
    pub title: &'static str,
    pub group: &'static str,
    pub default_on: bool,
    pub domains: &'static [&'static str],
}

macro_rules! p {
    ($n:expr, $t:expr, $g:expr, $on:expr, [$($d:expr),* $(,)?]) => {
        Preset { name: $n, title: $t, group: $g, default_on: $on, domains: &[$($d),*] }
    };
}

/// Built-in catalog. Operators can add their own groups from the panel.
pub const PRESETS: &[Preset] = &[
    p!("discord", "Discord", "social", true, ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media", "discordstatus.com"]),
    p!("telegram", "Telegram", "social", true, ["telegram.org", "t.me", "telegram.me", "telesco.pe"]),
    p!("social", "X / Instagram / Facebook / Reddit", "social", true, ["x.com", "twitter.com", "twimg.com", "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "whatsapp.com", "whatsapp.net", "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com"]),
    p!("media", "Spotify / Twitch / Kick", "media", true, ["spotify.com", "scdn.co", "twitch.tv", "ttvnw.net", "kick.com"]),
    p!("google", "Google / YouTube", "google", true, ["google.com", "youtube.com", "ytimg.com", "googlevideo.com", "gmail.com", "youtu.be"]),
    p!("ai_openai", "OpenAI / ChatGPT", "ai", true, ["openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"]),
    p!("ai_anthropic", "Anthropic / Claude", "ai", true, ["anthropic.com", "claude.ai", "claude.com"]),
    p!("ai_other", "Other AI platforms", "ai", true, ["perplexity.ai", "huggingface.co", "x.ai", "grok.com", "mistral.ai", "deepseek.com", "openrouter.ai", "cursor.com", "cursor.sh", "kaggle.com"]),
    p!("dev", "Developer 403 bypass", "dev", true, ["docker.io", "docker.com", "npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org", "gradle.org", "jetbrains.com", "tensorflow.org", "flutter.dev", "dart.dev", "developer.android.com", "hashicorp.com", "terraform.io"]),
    p!("riot", "Riot / Valorant / LoL", "gaming", true, ["riotgames.com", "leagueoflegends.com", "valorant.com", "playvalorant.com", "pvp.net"]),
    p!("steam", "Steam (store & login)", "gaming", true, ["steampowered.com", "steamcommunity.com", "steamstatic.com", "steamgames.com", "steam-chat.com"]),
    p!("epic", "Epic Games / Fortnite", "gaming", true, ["epicgames.com", "unrealengine.com", "fortnite.com"]),
    p!("blizzard", "Battle.net / Blizzard", "gaming", true, ["battle.net", "blizzard.com"]),
    p!("ea", "EA / Origin", "gaming", true, ["ea.com", "origin.com"]),
    p!("ubisoft", "Ubisoft", "gaming", true, ["ubisoft.com", "ubi.com"]),
    p!("activision", "Call of Duty / Activision", "gaming", true, ["callofduty.com", "activision.com"]),
    p!("pubg", "PUBG / Krafton", "gaming", true, ["pubg.com", "krafton.com"]),
    p!("hoyoverse", "Genshin / HSR / ZZZ", "gaming", true, ["hoyoverse.com", "mihoyo.com", "genshinimpact.com"]),
    p!("xbox", "Xbox Live", "console", true, ["xbox.com", "xboxlive.com"]),
    p!("playstation", "PlayStation Network", "console", true, ["playstation.com", "playstation.net", "sonyentertainmentnetwork.com"]),
    p!("nintendo", "Nintendo", "console", true, ["nintendo.com", "nintendo.net"]),
    p!("downloads", "Bulk game downloads (uses lots of bandwidth)", "bandwidth", false, ["steamcontent.com", "download.epicgames.com", "dl.playstation.net", "cdn.blizzard.com", "dlassets.xboxlive.com", "cdn.gog.com"]),
];
