//! Complete opaque source work on app↔daemon IPC. No inter-node representation.
use crate::ipc::{AppIpcSendPayload, RELAY_MEDIA_SEALED_MAGIC};
use veil_types::local_lossy_work::{MAX_CELLS, MAX_SEALED_BYTES};

pub struct LocalLossyBatchPayload {
    pub destination: [u8; 32],
    pub source_app: [u8; 32],
    pub destination_app: [u8; 32],
    pub endpoint: u32,
    pub cells: Vec<Vec<u8>>,
}

impl LocalLossyBatchPayload {
    pub fn encode(&self) -> Option<Vec<u8>> {
        if self.cells.is_empty() || self.cells.len() > MAX_CELLS {
            return None;
        }
        let bytes = self
            .cells
            .iter()
            .try_fold(0usize, |sum, cell| sum.checked_add(cell.len()))?;
        if bytes > MAX_SEALED_BYTES
            || self
                .cells
                .iter()
                .any(|c| c.len() < 36 || !c.starts_with(&RELAY_MEDIA_SEALED_MAGIC))
        {
            return None;
        }
        let mut body = Vec::with_capacity(102 + self.cells.len() * 4 + bytes);
        body.extend_from_slice(&self.destination);
        body.extend_from_slice(&self.source_app);
        body.extend_from_slice(&self.destination_app);
        body.extend_from_slice(&self.endpoint.to_be_bytes());
        body.extend_from_slice(&(self.cells.len() as u16).to_be_bytes());
        for cell in &self.cells {
            body.extend_from_slice(&(cell.len() as u32).to_be_bytes());
            body.extend_from_slice(cell);
        }
        Some(body)
    }

    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < 102 || body.len() > 102 + 4 * MAX_CELLS + MAX_SEALED_BYTES {
            return None;
        }
        let count = u16::from_be_bytes(body[100..102].try_into().ok()?) as usize;
        if count == 0 || count > MAX_CELLS {
            return None;
        }
        let mut cells = Vec::with_capacity(count);
        let mut cursor = 102usize;
        let mut total = 0usize;
        for _ in 0..count {
            let size = u32::from_be_bytes(body.get(cursor..cursor + 4)?.try_into().ok()?) as usize;
            cursor += 4;
            total = total.checked_add(size)?;
            if size < 36 || total > MAX_SEALED_BYTES {
                return None;
            }
            let cell = body.get(cursor..cursor.checked_add(size)?)?;
            if !cell.starts_with(&RELAY_MEDIA_SEALED_MAGIC) {
                return None;
            }
            cells.push(cell.to_vec());
            cursor += size;
        }
        if cursor != body.len() {
            return None;
        }
        Some(Self {
            destination: body[..32].try_into().ok()?,
            source_app: body[32..64].try_into().ok()?,
            destination_app: body[64..96].try_into().ok()?,
            endpoint: u32::from_be_bytes(body[96..100].try_into().ok()?),
            cells,
        })
    }

    pub fn into_sends(self) -> Vec<Vec<u8>> {
        self.cells
            .into_iter()
            .map(|data| {
                let mut body = AppIpcSendPayload {
                    dst_node_id: self.destination,
                    src_app_id: self.source_app,
                    app_id: self.destination_app,
                    endpoint_id: self.endpoint,
                    require_ack: false,
                    anonymous: false,
                    anonymous_authenticated: false,
                    expect_reply: false,
                    my_other_devices: false,
                    is_reply: false,
                    reply_id: 0,
                    reply_endpoint_id: 0,
                    data: veil_bufpool::pooled_shared_from_vec(data),
                }
                .encode();
                body[100..104].copy_from_slice(
                    &(crate::ipc::IPC_SEND_FLAG_RELAY_REALTIME
                        | crate::ipc::IPC_SEND_FLAG_RELAY_MEDIA_SEALED)
                        .to_be_bytes(),
                );
                body
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_group_roundtrip_and_fail_closed_bounds() {
        let cell = [RELAY_MEDIA_SEALED_MAGIC.as_slice(), &[7; 100]].concat();
        let batch = LocalLossyBatchPayload {
            destination: [1; 32],
            source_app: [2; 32],
            destination_app: [3; 32],
            endpoint: 9,
            cells: vec![cell.clone(); 3],
        };
        let bytes = batch.encode().unwrap();
        let decoded = LocalLossyBatchPayload::decode(&bytes).unwrap();
        assert_eq!(decoded.cells, batch.cells);
        let sends = decoded.into_sends();
        assert_eq!(sends.len(), 3);
        for body in sends {
            let send = AppIpcSendPayload::decode(&body).unwrap();
            assert_eq!(send.src_app_id, [2; 32]);
            assert_eq!(&*send.data, &cell);
            assert!(!send.require_ack && !send.anonymous && !send.my_other_devices);
        }
        for end in 0..bytes.len() {
            assert!(LocalLossyBatchPayload::decode(&bytes[..end]).is_none());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(LocalLossyBatchPayload::decode(&trailing).is_none());
        let mut invalid = bytes.clone();
        invalid[100..102].copy_from_slice(&513u16.to_be_bytes());
        assert!(LocalLossyBatchPayload::decode(&invalid).is_none());
        invalid = bytes.clone();
        invalid[102..106].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(LocalLossyBatchPayload::decode(&invalid).is_none());
        invalid = bytes;
        invalid[106] ^= 1;
        assert!(LocalLossyBatchPayload::decode(&invalid).is_none());
    }
}
