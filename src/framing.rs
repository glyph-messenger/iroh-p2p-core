use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{P2pError, Result};

pub const DEFAULT_MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

/// Read a length-prefixed frame (4-byte big endian length followed by payload) from an async stream.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R, max_size: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > max_size {
        return Err(P2pError::FrameTooLarge {
            size: len,
            max: max_size,
        });
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Write a length-prefixed frame (4-byte big endian length followed by payload) into an async stream.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, data: &[u8]) -> Result<()> {
    let len = data.len() as u32;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

/// Read and deserialize a bincode-encoded message from a length-prefixed stream.
pub async fn read_bincode_msg<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
    max_size: usize,
) -> Result<T> {
    let bytes = read_frame(reader, max_size).await?;
    let msg: T = bincode::deserialize(&bytes)?;
    Ok(msg)
}

/// Serialize a message to bincode and write it as a length-prefixed frame.
pub async fn write_bincode_msg<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    msg: &T,
) -> Result<()> {
    let bytes = bincode::serialize(msg)?;
    write_frame(writer, &bytes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
    struct TestMessage {
        id: u64,
        text: String,
    }

    #[tokio::test]
    async fn test_framing_roundtrip() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let sent = TestMessage {
            id: 12345,
            text: "Hello Iroh P2P Core".into(),
        };

        let write_task = tokio::spawn(async move {
            write_bincode_msg(&mut client, &sent).await.unwrap();
        });

        let received: TestMessage = read_bincode_msg(&mut server, DEFAULT_MAX_FRAME_SIZE)
            .await
            .unwrap();

        write_task.await.unwrap();
        assert_eq!(received.id, 12345);
        assert_eq!(received.text, "Hello Iroh P2P Core");
    }

    #[tokio::test]
    async fn test_oversized_frame_rejection() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        let large_payload = vec![0u8; 1024];
        let write_task = tokio::spawn(async move {
            let _ = write_frame(&mut client, &large_payload).await;
        });

        // Set max_size to 512 so it exceeds limit
        let res = read_frame(&mut server, 512).await;
        assert!(matches!(res, Err(P2pError::FrameTooLarge { .. })));

        let _ = write_task.await;
    }
}
