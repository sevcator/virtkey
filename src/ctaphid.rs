//! CTAPHID report framing for the FIDO HID transport.
//!
//! This module handles transport framing only. It does not implement CTAP2 commands or Windows
//! device enumeration; the VHF driver and authenticator command handler plug in around it.

use std::collections::HashMap;

pub const REPORT_SIZE: usize = 64;
pub const MAX_MESSAGE_SIZE: usize = 7_609;
const CHANNEL_SIZE: usize = 4;
const INITIAL_HEADER_SIZE: usize = CHANNEL_SIZE + 3;
const CONTINUATION_HEADER_SIZE: usize = CHANNEL_SIZE + 1;
const INITIAL_DATA_SIZE: usize = REPORT_SIZE - INITIAL_HEADER_SIZE;
const CONTINUATION_DATA_SIZE: usize = REPORT_SIZE - CONTINUATION_HEADER_SIZE;

/// FIDO HID report descriptor: one 64-byte input report and one 64-byte output report.
pub const FIDO_HID_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F Authenticator Device)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Variable, Absolute)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Variable, Absolute)
    0xC0, // End Collection
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub channel_id: u32,
    /// CTAPHID command byte, including its high bit (for example `0x86` for INIT).
    pub command: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    InvalidCommand,
    MessageTooLarge,
    UnexpectedContinuation,
    WrongSequence,
}

#[derive(Debug)]
struct Assembly {
    command: u8,
    expected_len: usize,
    next_sequence: u8,
    payload: Vec<u8>,
}

/// Reassembles CTAPHID messages from 64-byte HID reports, keyed by channel.
#[derive(Default)]
pub struct Assembler {
    active: HashMap<u32, Assembly>,
}

impl Assembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one HID report. Returns a complete message once all its fragments arrive.
    pub fn push(&mut self, report: &[u8]) -> Result<Option<Message>, FrameError> {
        if report.len() != REPORT_SIZE {
            return Err(FrameError::InvalidCommand);
        }

        let channel_id = u32::from_be_bytes([report[0], report[1], report[2], report[3]]);
        let tag = report[CHANNEL_SIZE];

        if tag & 0x80 != 0 {
            self.active.remove(&channel_id);
            let command = tag;
            let expected_len = u16::from_be_bytes([report[5], report[6]]) as usize;
            if expected_len > MAX_MESSAGE_SIZE {
                return Err(FrameError::MessageTooLarge);
            }
            let initial_len = expected_len.min(INITIAL_DATA_SIZE);
            let payload = report[INITIAL_HEADER_SIZE..INITIAL_HEADER_SIZE + initial_len].to_vec();
            if payload.len() == expected_len {
                return Ok(Some(Message {
                    channel_id,
                    command,
                    payload,
                }));
            }
            self.active.insert(
                channel_id,
                Assembly {
                    command,
                    expected_len,
                    next_sequence: 0,
                    payload,
                },
            );
            return Ok(None);
        }

        let Some(assembly) = self.active.get_mut(&channel_id) else {
            return Err(FrameError::UnexpectedContinuation);
        };
        if tag != assembly.next_sequence {
            self.active.remove(&channel_id);
            return Err(FrameError::WrongSequence);
        }
        assembly.next_sequence = assembly
            .next_sequence
            .checked_add(1)
            .ok_or(FrameError::WrongSequence)?;
        let remaining = assembly.expected_len - assembly.payload.len();
        let fragment_len = remaining.min(CONTINUATION_DATA_SIZE);
        assembly.payload.extend_from_slice(
            &report[CONTINUATION_HEADER_SIZE..CONTINUATION_HEADER_SIZE + fragment_len],
        );

        if assembly.payload.len() == assembly.expected_len {
            let assembly = self
                .active
                .remove(&channel_id)
                .expect("assembly was just found");
            return Ok(Some(Message {
                channel_id,
                command: assembly.command,
                payload: assembly.payload,
            }));
        }
        Ok(None)
    }

    pub fn cancel_channel(&mut self, channel_id: u32) {
        self.active.remove(&channel_id);
    }
}

/// Split a CTAPHID message into zero-padded fixed-size HID reports.
pub fn packetize(message: &Message) -> Result<Vec<[u8; REPORT_SIZE]>, FrameError> {
    if message.command & 0x80 == 0 {
        return Err(FrameError::InvalidCommand);
    }
    if message.payload.len() > MAX_MESSAGE_SIZE {
        return Err(FrameError::MessageTooLarge);
    }

    let mut reports = Vec::with_capacity(
        1 + message
            .payload
            .len()
            .saturating_sub(INITIAL_DATA_SIZE)
            .div_ceil(CONTINUATION_DATA_SIZE),
    );
    let mut first = [0u8; REPORT_SIZE];
    first[..4].copy_from_slice(&message.channel_id.to_be_bytes());
    first[4] = message.command;
    first[5..7].copy_from_slice(&(message.payload.len() as u16).to_be_bytes());
    let first_len = message.payload.len().min(INITIAL_DATA_SIZE);
    first[INITIAL_HEADER_SIZE..INITIAL_HEADER_SIZE + first_len]
        .copy_from_slice(&message.payload[..first_len]);
    reports.push(first);

    let mut offset = first_len;
    let mut sequence = 0u8;
    while offset < message.payload.len() {
        if sequence > 0x7f {
            return Err(FrameError::MessageTooLarge);
        }
        let mut continuation = [0u8; REPORT_SIZE];
        continuation[..4].copy_from_slice(&message.channel_id.to_be_bytes());
        continuation[4] = sequence;
        let len = (message.payload.len() - offset).min(CONTINUATION_DATA_SIZE);
        continuation[CONTINUATION_HEADER_SIZE..CONTINUATION_HEADER_SIZE + len]
            .copy_from_slice(&message.payload[offset..offset + len]);
        reports.push(continuation);
        offset += len;
        sequence += 1;
    }
    Ok(reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packetize_and_assemble_single_report() {
        let expected = Message {
            channel_id: 0x0102_0304,
            command: 0x83,
            payload: b"hello FIDO".to_vec(),
        };
        let reports = packetize(&expected).unwrap();
        assert_eq!(reports.len(), 1);

        let mut assembler = Assembler::new();
        assert_eq!(assembler.push(&reports[0]).unwrap(), Some(expected));
    }

    #[test]
    fn packetize_and_assemble_multiple_reports() {
        let expected = Message {
            channel_id: 0xA1B2_C3D4,
            command: 0x90,
            payload: (0..=255).cycle().take(700).collect(),
        };
        let reports = packetize(&expected).unwrap();
        assert!(reports.len() > 1);

        let mut assembler = Assembler::new();
        let mut actual = None;
        for report in reports {
            if let Some(message) = assembler.push(&report).unwrap() {
                actual = Some(message);
            }
        }
        assert_eq!(actual, Some(expected));
    }

    #[test]
    fn rejects_invalid_command_and_oversized_message() {
        let invalid = Message {
            channel_id: 1,
            command: 0x10,
            payload: vec![],
        };
        assert_eq!(packetize(&invalid), Err(FrameError::InvalidCommand));

        let oversized = Message {
            channel_id: 1,
            command: 0x90,
            payload: vec![0; MAX_MESSAGE_SIZE + 1],
        };
        assert_eq!(packetize(&oversized), Err(FrameError::MessageTooLarge));
    }

    #[test]
    fn rejects_out_of_order_continuation() {
        let message = Message {
            channel_id: 7,
            command: 0x90,
            payload: vec![5; 100],
        };
        let mut reports = packetize(&message).unwrap();
        assert!(reports.len() > 1);
        reports[1][4] = 1;

        let mut assembler = Assembler::new();
        assert_eq!(assembler.push(&reports[0]).unwrap(), None);
        assert_eq!(assembler.push(&reports[1]), Err(FrameError::WrongSequence));
    }
}
