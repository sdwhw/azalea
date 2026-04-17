//! Write packets to a stream.

use std::{
    fmt::Debug,
    io::{self, Read},
};

use azalea_buf::AzBufVar;
use azalea_crypto::Aes128CfbEnc;
use flate2::{Compression, bufread::ZlibEncoder};
use thiserror::Error;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tracing::trace;

use crate::{packets::ProtocolPacket, read::MAXIMUM_UNCOMPRESSED_LENGTH};

pub async fn write_packet<P, W>(
    packet: &P,
    stream: &mut W,
    compression_threshold: Option<u32>,
    cipher: &mut Option<Aes128CfbEnc>,
) -> io::Result<()>
where
    P: ProtocolPacket + Debug,
    W: AsyncWrite + Unpin + Send,
{
    trace!("Sending packet: {packet:?}");
    let raw_packet = serialize_packet(packet).unwrap();
    write_raw_packet(&raw_packet, stream, compression_threshold, cipher).await
}

pub fn serialize_packet<P: ProtocolPacket + Debug>(
    packet: &P,
) -> Result<Box<[u8]>, PacketEncodeError> {
    let mut buf = Vec::new();
    packet.id().azalea_write_var(&mut buf)?;
    packet.write(&mut buf)?;
    if buf.len() > MAXIMUM_UNCOMPRESSED_LENGTH as usize {
        return Err(PacketEncodeError::TooBig {
            actual: buf.len(),
            maximum: MAXIMUM_UNCOMPRESSED_LENGTH as usize,
            packet_string: format!("{packet:?}"),
        });
    }
    Ok(buf.into_boxed_slice())
}

/// Serialize `packet` and append its framed wire bytes to `buf`.
///
/// Emits a 3-byte overlong varint.
/// `MAX_FRAME_BODY` (2 MiB - 1).
///
/// On error, `buf` is truncated back to its original length.
pub fn serialize_packet_into<P: ProtocolPacket + Debug>(
    packet: &P,
    buf: &mut Vec<u8>,
) -> Result<(), PacketEncodeError> {
    const MAX_FRAME_BODY: usize = (1 << 21) - 1;

    let start = buf.len();
    buf.extend_from_slice(&[0u8; 3]);
    let body_start = buf.len();

    let res = packet
        .id()
        .azalea_write_var(buf)
        .and_then(|_| packet.write(buf));
    if let Err(err) = res {
        buf.truncate(start);
        return Err(err.into());
    }

    let body_len = buf.len() - body_start;
    if body_len > MAX_FRAME_BODY {
        buf.truncate(start);
        return Err(PacketEncodeError::TooBig {
            actual: body_len,
            maximum: MAX_FRAME_BODY,
            packet_string: format!("{packet:?}"),
        });
    }

    let len = body_len as u32;
    buf[start]     = ((len      ) & 0x7F) as u8 | 0x80;
    buf[start + 1] = ((len >>  7) & 0x7F) as u8 | 0x80;
    buf[start + 2] = ((len >> 14) & 0x7F) as u8;
    Ok(())
}

pub async fn write_raw_packet<W>(
    raw_packet: &[u8],
    stream: &mut W,
    compression_threshold: Option<u32>,
    cipher: &mut Option<Aes128CfbEnc>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin + Send,
{
    let network_packet = encode_to_network_packet(raw_packet, compression_threshold, cipher);
    stream.write_all(&network_packet).await
}

pub fn encode_to_network_packet(
    raw_packet: &[u8],
    compression_threshold: Option<u32>,
    cipher: &mut Option<Aes128CfbEnc>,
) -> Vec<u8> {
    trace!("Writing raw packet: {raw_packet:?}");
    let mut raw_packet = raw_packet.to_vec();
    if let Some(threshold) = compression_threshold {
        raw_packet = compression_encoder(&raw_packet, threshold).unwrap();
    }
    raw_packet = frame_prepender(raw_packet).unwrap();
    // if we were given a cipher, encrypt the packet
    if let Some(cipher) = cipher {
        azalea_crypto::encrypt_packet(cipher, &mut raw_packet);
    }
    raw_packet
}

pub fn compression_encoder(
    data: &[u8],
    compression_threshold: u32,
) -> Result<Vec<u8>, PacketCompressError> {
    let n = data.len();
    // if it's less than the compression threshold, don't compress
    if n < compression_threshold as usize {
        let mut buf = Vec::new();
        0_u32.azalea_write_var(&mut buf)?;
        io::Write::write_all(&mut buf, data)?;
        Ok(buf)
    } else {
        // otherwise, compress
        let mut deflater = ZlibEncoder::new(data, Compression::default());

        // write deflated data to buf
        let mut compressed_data = Vec::new();
        deflater.read_to_end(&mut compressed_data)?;

        // prepend the length
        let mut len_prepended_compressed_data = Vec::new();
        (data.len() as u32).azalea_write_var(&mut len_prepended_compressed_data)?;
        len_prepended_compressed_data.append(&mut compressed_data);

        Ok(len_prepended_compressed_data)
    }
}

/// Prepend the length of the packet to it.
fn frame_prepender(mut data: Vec<u8>) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::new();
    (data.len() as u32).azalea_write_var(&mut buf)?;
    buf.append(&mut data);
    Ok(buf)
}

#[derive(Debug, Error)]
pub enum PacketEncodeError {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("Packet too big (is {actual} bytes, should be less than {maximum}): {packet_string}")]
    TooBig {
        actual: usize,
        maximum: usize,
        packet_string: String,
    },
}

#[derive(Debug, Error)]
pub enum PacketCompressError {
    #[error("{0}")]
    Io(#[from] io::Error),
}
