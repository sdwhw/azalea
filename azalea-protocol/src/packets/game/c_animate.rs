use azalea_buf::AzBuf;
use azalea_protocol_macros::ClientboundGamePacket;
use azalea_core::entity_id::MinecraftEntityId;

#[derive(AzBuf, ClientboundGamePacket, Clone, Debug, PartialEq)]
pub struct ClientboundAnimate {
    #[var]
    pub id: MinecraftEntityId,
    pub action: AnimationAction,
}

// minecraft actually uses a u8 for this, but a varint still works and makes it
// so i don't have to add a special handler
#[derive(AzBuf, Clone, Copy, Debug, PartialEq)]
pub enum AnimationAction {
    WakeUp = 0,
    CriticalHit = 1,
    MagicCriticalHit = 2,
}
