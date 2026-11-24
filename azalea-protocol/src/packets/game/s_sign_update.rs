use azalea_buf::AzBuf;
use azalea_core::position::BlockPos;
use azalea_protocol_macros::ServerboundGamePacket;

#[derive(AzBuf, Clone, Debug, PartialEq, ServerboundGamePacket)]
pub struct ServerboundSignUpdate {
    pub pos: BlockPos,
    pub lines: [String; 4],
    // a `SignTextSlot` varint in vanilla (0 = back, 1 = front), which is
    // wire-compatible with a bool
    pub is_front_text: bool,
}
