//! Bound newline-delimited input before handing it to the SDK's line buffer.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub(super) struct BoundedStdioRead<R> {
    inner: R,
    frame_bytes: usize,
    maximum: usize,
    oversized: Arc<AtomicBool>,
}

impl<R> BoundedStdioRead<R> {
    pub(super) fn new(inner: R) -> (Self, Arc<AtomicBool>) {
        let oversized = Arc::new(AtomicBool::new(false));
        (
            Self {
                inner,
                frame_bytes: 0,
                maximum: MAX_FRAME_BYTES,
                oversized: oversized.clone(),
            },
            oversized,
        )
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoundedStdioRead<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let too_large =
            || io::Error::new(io::ErrorKind::InvalidData, "MCP input frame exceeds limit");
        if this.oversized.load(Ordering::Relaxed) {
            return Poll::Ready(Err(too_large()));
        }
        // The fixed scratch buffer bounds reads even when the SDK requests a
        // large chunk. Newline accounting persists across Pending/split reads.
        let mut bytes = [0; 8192];
        let capacity = output.remaining().min(bytes.len());
        let mut input = ReadBuf::new(&mut bytes[..capacity]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut input) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }
        let input = input.filled();
        for (index, byte) in input.iter().enumerate() {
            if *byte == b'\n' {
                this.frame_bytes = 0;
            } else {
                this.frame_bytes += 1;
                if this.frame_bytes > this.maximum {
                    this.oversized.store(true, Ordering::Relaxed);
                    // Deliver earlier complete frames in the same read before
                    // returning an error on the next poll. They must not vanish
                    // merely because a later frame exceeded the bound.
                    if index > 0 {
                        output.put_slice(&input[..index]);
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(too_large()));
                }
            }
        }
        output.put_slice(input);
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    #[tokio::test]
    async fn frame_bound_survives_split_reads_and_resets_at_newlines() {
        let (input, mut writer) = tokio::io::duplex(3);
        let writing = tokio::spawn(async move {
            for chunk in [b"ab".as_slice(), b"cd\n1", b"234\n", b"xy"] {
                writer.write_all(chunk).await.unwrap();
            }
        });
        let (mut bounded, oversized) = BoundedStdioRead::new(input);
        bounded.maximum = 4;
        let mut actual = Vec::new();
        bounded.read_to_end(&mut actual).await.unwrap();
        writing.await.unwrap();
        assert_eq!(actual, b"abcd\n1234\nxy");
        assert!(!oversized.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn oversized_frame_preserves_preceding_complete_messages() {
        let (mut bounded, oversized) = BoundedStdioRead::new(b"ok\n12345\n".as_slice());
        bounded.maximum = 4;
        let mut reader = BufReader::new(bounded);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "ok\n");
        line.clear();
        let error = reader.read_line(&mut line).await.unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(oversized.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn oversized_unterminated_frame_is_bounded_across_reads() {
        let (mut bounded, oversized) = BoundedStdioRead::new(b"12345".as_slice());
        bounded.maximum = 4;
        let mut buffer = [0; 2];
        assert_eq!(bounded.read(&mut buffer).await.unwrap(), 2);
        assert_eq!(bounded.read(&mut buffer).await.unwrap(), 2);
        assert_eq!(
            bounded.read(&mut buffer).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(oversized.load(Ordering::Relaxed));
    }
}
