use std::io::{self, Cursor, Write};

use azalea_buf::{AzBuf, AzBufVar, BufReadError, BufReadErrorRepr};
use azalea_chat::translatable_component::TranslatableComponent;
use tracing::debug;

/// A Minecraft gamemode, like survival or creative.
///
/// When this is used as a component, it is only present for local players. For
/// non-local players, their gamemode must be looked up in the tab list.
#[cfg_attr(feature = "bevy_ecs", derive(bevy_ecs::component::Component))]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum GameMode {
    #[default]
    Survival,
    Creative,
    Adventure,
    Spectator,
}

impl GameMode {
    pub fn to_id(&self) -> u8 {
        match self {
            GameMode::Survival => 0,
            GameMode::Creative => 1,
            GameMode::Adventure => 2,
            GameMode::Spectator => 3,
        }
    }

    /// Get the ID of the game mode, but return -1 if the game type is invalid.
    pub fn to_optional_id<T: Into<Option<GameMode>>>(game_type: T) -> i8 {
        match game_type.into() {
            Some(game_type) => game_type.to_id() as i8,
            None => -1,
        }
    }

    pub fn from_id(id: u8) -> Option<GameMode> {
        Some(match id {
            0 => GameMode::Survival,
            1 => GameMode::Creative,
            2 => GameMode::Adventure,
            3 => GameMode::Spectator,
            _ => return None,
        })
    }

    pub fn from_optional_id(id: i8) -> Option<OptionalGameType> {
        Some(
            match id {
                -1 => None,
                id => Some(GameMode::from_id(id as u8)?),
            }
            .into(),
        )
    }

    /// The short translatable display name for the gamemode, like "Survival".
    pub fn short_name(&self) -> TranslatableComponent {
        TranslatableComponent::new(format!("selectWorld.gameMode.{}", self.name()), vec![])
    }

    /// The long translatable display name for the gamemode, like "Survival
    /// Mode".
    pub fn long_name(&self) -> TranslatableComponent {
        TranslatableComponent::new(format!("gameMode.{}", self.name()), vec![])
    }

    pub fn from_name(name: &str) -> GameMode {
        match name {
            "survival" => GameMode::Survival,
            "creative" => GameMode::Creative,
            "adventure" => GameMode::Adventure,
            "spectator" => GameMode::Spectator,
            _ => panic!("Unknown game type name: {name}"),
        }
    }

    /// The internal name for the game mode, like "survival".
    pub fn name(&self) -> &'static str {
        match self {
            GameMode::Survival => "survival",
            GameMode::Creative => "creative",
            GameMode::Adventure => "adventure",
            GameMode::Spectator => "spectator",
        }
    }
}

impl GameMode {
    /// Whether the player can't interact with blocks while in this game mode.
    ///
    /// Returns true if you're in adventure or spectator.
    pub fn is_block_placing_restricted(&self) -> bool {
        matches!(self, GameMode::Adventure | GameMode::Spectator)
    }
}

impl AzBuf for GameMode {
    fn azalea_read(buf: &mut Cursor<&[u8]>) -> Result<Self, BufReadError> {
        let id = u32::azalea_read_var(buf)?;
        let id = id.try_into().unwrap_or_else(|_| {
            debug!("Unknown game mode id {id}, defaulting to survival");
            0
        });
        Ok(GameMode::from_id(id).unwrap_or_else(|| {
            debug!("Unknown game mode id {id}, defaulting to survival");
            GameMode::Survival
        }))
    }
    fn azalea_write(&self, buf: &mut impl Write) -> io::Result<()> {
        u8::azalea_write(&self.to_id(), buf)
    }
}

/// Rust doesn't let us `impl AzBuf for Option<GameType>` so we have to
/// make a new type :(
#[derive(Clone, Copy, Debug, Hash, PartialEq)]
pub struct OptionalGameType(pub Option<GameMode>);

impl From<Option<GameMode>> for OptionalGameType {
    fn from(game_type: Option<GameMode>) -> Self {
        OptionalGameType(game_type)
    }
}

impl From<OptionalGameType> for Option<GameMode> {
    fn from(optional_game_type: OptionalGameType) -> Self {
        optional_game_type.0
    }
}

impl AzBuf for OptionalGameType {
    fn azalea_read(buf: &mut Cursor<&[u8]>) -> Result<Self, BufReadError> {
        let raw = u32::azalea_read_var(buf)?;
        let Some(id) = raw.checked_sub(1) else {
            return Ok(OptionalGameType(None));
        };
        u8::try_from(id)
            .ok()
            .and_then(GameMode::from_id)
            .map(|game_mode| OptionalGameType(Some(game_mode)))
            .ok_or(BufReadErrorRepr::UnexpectedEnumVariant { id: id as i32 }.into())
    }
    fn azalea_write(&self, buf: &mut impl Write) -> io::Result<()> {
        let raw = match self.0 {
            Some(game_mode) => game_mode.to_id() as u32 + 1,
            None => 0,
        };
        raw.azalea_write_var(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optional_game_type_is_optional_varint() {
        for (value, bytes) in [
            (OptionalGameType(None), vec![0u8]),
            (OptionalGameType(Some(GameMode::Survival)), vec![1]),
            (OptionalGameType(Some(GameMode::Spectator)), vec![4]),
        ] {
            let mut buf = Vec::new();
            value.azalea_write(&mut buf).unwrap();
            assert_eq!(buf, bytes);
            let read = OptionalGameType::azalea_read(&mut Cursor::new(&buf[..])).unwrap();
            assert_eq!(read, value);
        }
        assert!(OptionalGameType::azalea_read(&mut Cursor::new(&[5u8][..])).is_err());
    }
}
