//! Cancellation-safe ordered framing. Waiting for a partial frame must not
//! prevent the session loop from admitting independent outbound datagrams.
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::SemaphorePermit;
use tokio::time::Instant;
use veil_proto::header::{FrameHeader, HEADER_SIZE};

#[derive(Debug)]
pub enum ReadError {
    Closed(String),
    BadHeader(String),
    BodyBudget(usize),
    BodyTimeout,
}

pub struct Frame {
    pub header: FrameHeader,
    pub body: veil_bufpool::Pooled,
    pub body_budget: Option<SemaphorePermit<'static>>,
    pub body_elapsed: std::time::Duration,
}

#[derive(Default)]
pub struct Reader {
    header_bytes: [u8; HEADER_SIZE],
    header_used: usize,
    header: Option<FrameHeader>,
    body: Option<veil_bufpool::Pooled>,
    body_used: usize,
    body_budget: Option<SemaphorePermit<'static>>,
    budget_deadline: Option<Instant>,
    body_deadline: Option<Instant>,
    body_started: Option<Instant>,
    progress: Option<Instant>,
}

impl Reader {
    pub fn has_partial_frame(&self) -> bool {
        self.header_used != 0
    }
    pub fn take_progress(&mut self) -> Option<(Instant, Option<(u8, u16)>)> {
        self.progress.take().map(|at| {
            (
                at,
                self.header
                    .as_ref()
                    .map(|header| (header.family, header.msg_type)),
            )
        })
    }

    pub async fn read<R: AsyncRead + Unpin>(
        &mut self,
        input: &mut R,
        max_body: u32,
    ) -> Result<Frame, ReadError> {
        while self.header_used < HEADER_SIZE {
            // read(), unlike read_exact(), is cancellation-safe. Save each
            // successful cursor movement synchronously before the next await.
            let n = input
                .read(&mut self.header_bytes[self.header_used..])
                .await
                .map_err(|e| ReadError::Closed(e.to_string()))?;
            if n == 0 {
                return Err(ReadError::Closed("EOF in frame header".into()));
            }
            self.header_used += n;
            self.progress = Some(Instant::now());
        }
        if self.header.is_none() {
            self.header = Some(
                veil_proto::codec::decode_header_with_limit(&self.header_bytes, max_body)
                    .map_err(|e| ReadError::BadHeader(e.to_string()))?,
            );
        }
        let header = self.header.as_ref().unwrap();
        let length = header.body_len as usize;
        if self.body.is_none() {
            if length > 0 {
                let deadline = *self
                    .budget_deadline
                    .get_or_insert_with(|| Instant::now() + super::BODY_BUDGET_DEADLINE);
                self.body_budget = Some(
                    tokio::time::timeout_at(deadline, crate::rx_body_budget::reserve(length))
                        .await
                        .map_err(|_| ReadError::BodyBudget(length))?,
                );
            }
            let mut body = veil_bufpool::global().acquire(length);
            body.as_vec_mut().resize(length, 0);
            self.body = Some(body);
            let now = Instant::now();
            self.body_started = Some(now);
            self.body_deadline = Some(now + super::BODY_DEADLINE);
        }
        while self.body_used < length {
            let n = tokio::time::timeout_at(
                self.body_deadline.unwrap(),
                input.read(&mut self.body.as_mut().unwrap()[self.body_used..]),
            )
            .await
            .map_err(|_| ReadError::BodyTimeout)?
            .map_err(|e| ReadError::Closed(e.to_string()))?;
            if n == 0 {
                return Err(ReadError::Closed("EOF in frame body".into()));
            }
            self.body_used += n;
            self.progress = Some(Instant::now());
        }
        let frame = Frame {
            header: self.header.take().unwrap(),
            body: self.body.take().unwrap(),
            body_budget: self.body_budget.take(),
            body_elapsed: self.body_started.take().unwrap().elapsed(),
        };
        self.header_used = 0;
        self.body_used = 0;
        self.budget_deadline = None;
        self.body_deadline = None;
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;

    fn encoded(data: &[u8]) -> Vec<u8> {
        let mut header = FrameHeader::new(4, 1);
        header.body_len = data.len() as u32;
        let mut wire = veil_proto::codec::encode_header(&header).to_vec();
        wire.extend_from_slice(data);
        wire
    }

    #[tokio::test]
    async fn cancellations_preserve_partial_header_body_and_next_frame() {
        let (mut tx, mut rx) = tokio::io::duplex(8192);
        let first = encoded(&vec![0x71; 3200]);
        let second = encoded(b"next frame");
        let mut reader = Reader::default();
        for range in [0..3, 3..HEADER_SIZE + 17, HEADER_SIZE + 17..first.len() - 1] {
            tx.write_all(&first[range]).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(2), reader.read(&mut rx, 4096))
                    .await
                    .is_err()
            );
            assert!(reader.has_partial_frame());
        }
        tx.write_all(&first[first.len() - 1..]).await.unwrap();
        tx.write_all(&second).await.unwrap();
        let frame = reader.read(&mut rx, 4096).await.unwrap();
        assert_eq!(&frame.body[..], &first[HEADER_SIZE..]);
        assert!(frame.body_budget.is_some());
        drop(frame);
        assert!(!reader.has_partial_frame());
        let next = reader.read(&mut rx, 4096).await.unwrap();
        assert_eq!(&next.body[..], b"next frame");
    }

    #[tokio::test]
    async fn cancellations_do_not_extend_the_body_deadline() {
        let (mut tx, mut rx) = tokio::io::duplex(128);
        tx.write_all(&encoded(&[7; 64])[..HEADER_SIZE + 1])
            .await
            .unwrap();
        let mut reader = Reader::default();
        assert!(
            tokio::time::timeout(Duration::from_millis(2), reader.read(&mut rx, 1024))
                .await
                .is_err()
        );
        reader.body_deadline = Some(Instant::now() + Duration::from_millis(20));
        for _ in 0..3 {
            assert!(
                tokio::time::timeout(Duration::from_millis(2), reader.read(&mut rx, 1024))
                    .await
                    .is_err()
            );
        }
        assert!(matches!(
            reader.read(&mut rx, 1024).await,
            Err(ReadError::BodyTimeout)
        ));
    }

    #[tokio::test]
    async fn oversized_header_is_rejected_before_reservation_or_allocation() {
        let (mut tx, mut rx) = tokio::io::duplex(128);
        tx.write_all(&encoded(&[7; 64])[..HEADER_SIZE])
            .await
            .unwrap();
        let mut reader = Reader::default();
        assert!(matches!(
            reader.read(&mut rx, 32).await,
            Err(ReadError::BadHeader(_))
        ));
        assert!(reader.body_budget.is_none());
        assert!(reader.body.is_none());
    }
}
