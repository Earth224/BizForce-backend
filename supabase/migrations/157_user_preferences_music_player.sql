-- 157_user_preferences_music_player.sql — the boombox-mixer's own settings.
--
-- WHY. The music player is a boombox-mixer with a finish (chrome or black)
-- and a three-band EQ (bass, mid, treble, each -12 to +12 dB). A member sets
-- them once and the boombox looks and sounds the same on every device they
-- sign in on.
--
-- user_preferences.music_player holds them as JSON, validated in the API
-- (lib/music.js playerSettings) against a CLOSED shape:
--   { "finish": "chrome" | "black",
--     "eq": { "bass": n, "mid": n, "treble": n } }   n in -12 … 12, half-dB steps
-- Anything else is refused with a 400 naming the field, and what is read back
-- goes through storedPlayer, which keeps only the valid parts. The CHECK below
-- is the floor under that (an object, a small size). NULL means the defaults
-- (chrome, a flat EQ).
--
-- Until this is applied, GET and PUT /api/music/player answer 503 with a plain
-- sentence, and the player keeps the settings on the device (bf_music).
--
-- The column is part of the member's user_preferences row, so it is in the
-- data export and deleted with the account like the rest of that row
-- (lib/yourData.js). user_preferences already has row level security on
-- (migration 030).

ALTER TABLE public.user_preferences
  ADD COLUMN IF NOT EXISTS music_player jsonb;

ALTER TABLE public.user_preferences
  DROP CONSTRAINT IF EXISTS user_preferences_music_player_check;
ALTER TABLE public.user_preferences
  ADD CONSTRAINT user_preferences_music_player_check CHECK (
    music_player IS NULL OR (jsonb_typeof(music_player) = 'object' AND pg_column_size(music_player) <= 1024)
  );
