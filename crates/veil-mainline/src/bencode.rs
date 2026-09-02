//! Bencode, the encoding BEP 5 speaks.
//!
//! Written here rather than taken from a crate, for one reason: every byte
//! this parses arrives from an open network, unsolicited, from whoever cares
//! to send it. That is the smallest possible amount of trust, and it is worth
//! having the parser be something this repository can read in one sitting and
//! bound explicitly — depth, length, and count — rather than something whose
//! bounds are somebody else's business.
//!
//! Bencode has four types: integers `i…e`, byte strings `<len>:<bytes>`,
//! lists `l…e` and dictionaries `d…e`. Dictionary keys are byte strings and
//! the spec requires them sorted; encoding here always sorts, and decoding
//! rejects an unsorted or repeated key rather than accepting it, because two
//! parsers that disagree about a message's meaning is how one node is made to
//! see something another does not.

use std::collections::BTreeMap;

/// Deepest nesting accepted. Real KRPC messages nest three or four deep; this
/// is room to spare and a bound on recursion, which is the only way this
/// parser could be made to exhaust the stack.
pub const MAX_DEPTH: usize = 16;

/// Longest byte string accepted. A KRPC packet arrives in one UDP datagram,
/// so nothing legitimate approaches this.
pub const MAX_BYTES_LEN: usize = 64 * 1024;

/// Most entries in one list or dictionary.
pub const MAX_ITEMS: usize = 4096;

/// A bencode value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Bytes(Vec<u8>),
    List(Vec<Value>),
    Dict(BTreeMap<Vec<u8>, Value>),
}

/// Why a message was refused.
///
/// Deliberately coarse: the sender is anonymous and unsolicited, so the only
/// action any of these supports is dropping the datagram. A finer taxonomy
/// would exist to be logged, and logging one line per malformed packet on a
/// public DHT is a way to be flooded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Ran out of input in the middle of a value.
    Truncated,
    /// A byte that cannot start or continue a value here.
    Malformed,
    /// Nested past [`MAX_DEPTH`], or longer/larger than the other bounds.
    TooBig,
    /// An integer with a leading zero, a lone minus, or `-0` — all of which
    /// bencode forbids and all of which give two encodings of one number.
    NotCanonicalInt,
    /// Dictionary keys out of order or repeated.
    NotCanonicalDict,
    /// Bytes left over after a complete value.
    TrailingBytes,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Truncated => "truncated",
            Self::Malformed => "malformed",
            Self::TooBig => "past a size bound",
            Self::NotCanonicalInt => "non-canonical integer",
            Self::NotCanonicalDict => "dictionary keys unsorted or repeated",
            Self::TrailingBytes => "trailing bytes after the value",
        })
    }
}

impl std::error::Error for DecodeError {}

/// Decode exactly one value, which must consume the whole input.
pub fn decode(input: &[u8]) -> Result<Value, DecodeError> {
    let mut p = Parser { input, at: 0 };
    let value = p.value(0)?;
    if p.at != input.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [u8],
    at: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Result<u8, DecodeError> {
        self.input
            .get(self.at)
            .copied()
            .ok_or(DecodeError::Truncated)
    }

    fn value(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::TooBig);
        }
        match self.peek()? {
            b'i' => self.integer(),
            b'l' => self.list(depth),
            b'd' => self.dict(depth),
            b'0'..=b'9' => self.bytes().map(Value::Bytes),
            _ => Err(DecodeError::Malformed),
        }
    }

    fn integer(&mut self) -> Result<Value, DecodeError> {
        debug_assert_eq!(self.input.get(self.at), Some(&b'i'));
        self.at += 1;
        let start = self.at;
        while self.peek()? != b'e' {
            self.at += 1;
            if self.at - start > 24 {
                return Err(DecodeError::TooBig);
            }
        }
        let digits = &self.input[start..self.at];
        self.at += 1; // the 'e'
        let text = std::str::from_utf8(digits).map_err(|_| DecodeError::Malformed)?;

        // Canonical form only. `i-0e`, `i03e` and `ie` are all forbidden, and
        // accepting them would give two spellings of one number — which is a
        // way to make two nodes disagree about what a message said.
        let body = text.strip_prefix('-').unwrap_or(text);
        // Digits and nothing else. Rust's own integer parser accepts a leading
        // `+`, bencode does not, and `i+3e` got through this check looking
        // canonical until a test asked.
        if body.is_empty()
            || !body.bytes().all(|b| b.is_ascii_digit())
            || (body.len() > 1 && body.starts_with('0'))
            || (text.starts_with('-') && body == "0")
        {
            return Err(DecodeError::NotCanonicalInt);
        }
        text.parse::<i64>()
            .map(Value::Int)
            .map_err(|_| DecodeError::NotCanonicalInt)
    }

    fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        let start = self.at;
        while self.peek()? != b':' {
            if !self.peek()?.is_ascii_digit() {
                return Err(DecodeError::Malformed);
            }
            self.at += 1;
            if self.at - start > 10 {
                return Err(DecodeError::TooBig);
            }
        }
        let digits = &self.input[start..self.at];
        self.at += 1; // the ':'
        if digits.is_empty() || (digits.len() > 1 && digits[0] == b'0') {
            return Err(DecodeError::NotCanonicalInt);
        }
        let len: usize = std::str::from_utf8(digits)
            .map_err(|_| DecodeError::Malformed)?
            .parse()
            .map_err(|_| DecodeError::TooBig)?;
        if len > MAX_BYTES_LEN {
            return Err(DecodeError::TooBig);
        }
        let end = self.at.checked_add(len).ok_or(DecodeError::TooBig)?;
        let slice = self.input.get(self.at..end).ok_or(DecodeError::Truncated)?;
        self.at = end;
        Ok(slice.to_vec())
    }

    fn list(&mut self, depth: usize) -> Result<Value, DecodeError> {
        self.at += 1; // the 'l'
        let mut items = Vec::new();
        while self.peek()? != b'e' {
            if items.len() >= MAX_ITEMS {
                return Err(DecodeError::TooBig);
            }
            items.push(self.value(depth + 1)?);
        }
        self.at += 1; // the 'e'
        Ok(Value::List(items))
    }

    fn dict(&mut self, depth: usize) -> Result<Value, DecodeError> {
        self.at += 1; // the 'd'
        let mut map = BTreeMap::new();
        let mut previous: Option<Vec<u8>> = None;
        while self.peek()? != b'e' {
            if map.len() >= MAX_ITEMS {
                return Err(DecodeError::TooBig);
            }
            if !self.peek()?.is_ascii_digit() {
                return Err(DecodeError::Malformed);
            }
            let key = self.bytes()?;
            if let Some(ref last) = previous
                && *last >= key
            {
                return Err(DecodeError::NotCanonicalDict);
            }
            previous = Some(key.clone());
            let value = self.value(depth + 1)?;
            map.insert(key, value);
        }
        self.at += 1; // the 'e'
        Ok(Value::Dict(map))
    }
}

/// Encode a value. Dictionary keys come out sorted, because [`BTreeMap`] keeps
/// them that way and bencode requires it.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_into(value, &mut out);
    out
}

fn write_into(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Int(n) => {
            out.push(b'i');
            out.extend_from_slice(n.to_string().as_bytes());
            out.push(b'e');
        }
        Value::Bytes(b) => {
            out.extend_from_slice(b.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(b);
        }
        Value::List(items) => {
            out.push(b'l');
            for item in items {
                write_into(item, out);
            }
            out.push(b'e');
        }
        Value::Dict(map) => {
            out.push(b'd');
            for (key, item) in map {
                out.extend_from_slice(key.len().to_string().as_bytes());
                out.push(b':');
                out.extend_from_slice(key);
                write_into(item, out);
            }
            out.push(b'e');
        }
    }
}

/// Conveniences for reading a KRPC message without a match arm at every step.
impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Self::List(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&BTreeMap<Vec<u8>, Value>> {
        match self {
            Self::Dict(map) => Some(map),
            _ => None,
        }
    }

    /// The value at `key` of a dictionary, or `None` for anything else.
    pub fn get(&self, key: &[u8]) -> Option<&Value> {
        self.as_dict()?.get(key)
    }
}

/// Build a dictionary without spelling out `BTreeMap` at every call site.
pub fn dict<const N: usize>(entries: [(&[u8], Value); N]) -> Value {
    dict_of(entries)
}

/// The same, from anything iterable — for a message whose set of keys is
/// decided at run time rather than written out.
pub fn dict_of<'a>(entries: impl IntoIterator<Item = (&'a [u8], Value)>) -> Value {
    Value::Dict(
        entries
            .into_iter()
            .map(|(k, v)| (k.to_vec(), v))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// A byte string from anything that looks like one.
pub fn bytes(value: impl AsRef<[u8]>) -> Value {
    Value::Bytes(value.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(value: Value) {
        let wire = encode(&value);
        let back = decode(&wire).unwrap_or_else(|e| panic!("{value:?} did not survive: {e}"));
        assert_eq!(back, value);
        assert_eq!(
            encode(&back),
            wire,
            "encoding is not stable across a round trip"
        );
    }

    #[test]
    fn the_four_types_survive_the_wire() {
        round_trip(Value::Int(0));
        round_trip(Value::Int(-1));
        round_trip(Value::Int(i64::MAX));
        round_trip(Value::Int(i64::MIN));
        round_trip(bytes(""));
        round_trip(bytes("announce_peer"));
        round_trip(Value::Bytes(vec![0, 255, 128, 7]));
        round_trip(Value::List(vec![]));
        round_trip(Value::List(vec![Value::Int(1), bytes("two")]));
        round_trip(dict([]));
        round_trip(dict([(b"a", Value::Int(1)), (b"b", bytes("x"))]));
    }

    #[test]
    fn a_real_krpc_query_reads_the_way_the_bep_says() {
        // BEP 5's own example, byte for byte:
        //   ping Query = {"t":"aa", "y":"q", "q":"ping", "a":{"id":"abcdefghij0123456789"}}
        let wire = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
        let msg = decode(wire).expect("the BEP's own example must parse");
        assert_eq!(msg.get(b"y").and_then(Value::as_bytes), Some(&b"q"[..]));
        assert_eq!(msg.get(b"q").and_then(Value::as_bytes), Some(&b"ping"[..]));
        assert_eq!(msg.get(b"t").and_then(Value::as_bytes), Some(&b"aa"[..]));
        assert_eq!(
            msg.get(b"a")
                .and_then(|a| a.get(b"id"))
                .and_then(Value::as_bytes),
            Some(&b"abcdefghij0123456789"[..])
        );
        // And it re-encodes to exactly the bytes it came from, which is what
        // makes us indistinguishable from every other client on that wire.
        assert_eq!(encode(&msg), wire);
    }

    #[test]
    fn a_binary_key_and_a_binary_value_are_not_text() {
        // `nodes` in a find_node response is 26 bytes per node, none of it
        // UTF-8. A parser that insists on text drops every useful answer.
        let compact: Vec<u8> = (0u8..=25).collect();
        let msg = dict([(b"nodes", Value::Bytes(compact.clone()))]);
        let back = decode(&encode(&msg)).unwrap();
        assert_eq!(
            back.get(b"nodes").and_then(Value::as_bytes),
            Some(&compact[..])
        );
    }

    #[test]
    fn two_spellings_of_one_number_are_both_refused() {
        // Canonical form matters here for a specific reason: a node that
        // accepts `i03e` and one that does not will disagree about whether
        // two messages are the same message.
        for bad in [
            &b"i-0e"[..],
            b"i03e",
            b"i-03e",
            b"ie",
            b"i-e",
            b"i+3e",
            b"i3",
            b"i 3e",
        ] {
            assert!(
                decode(bad).is_err(),
                "{:?} was accepted",
                String::from_utf8_lossy(bad)
            );
        }
        assert_eq!(decode(b"i0e"), Ok(Value::Int(0)), "plain zero is legal");
    }

    #[test]
    fn a_dictionary_with_unsorted_or_repeated_keys_is_refused() {
        // Two parsers that disagree about which value wins is how one node is
        // made to see something another does not.
        assert_eq!(
            decode(b"d1:bi1e1:ai2ee").err(),
            Some(DecodeError::NotCanonicalDict)
        );
        assert_eq!(
            decode(b"d1:ai1e1:ai2ee").err(),
            Some(DecodeError::NotCanonicalDict)
        );
        assert!(decode(b"d1:ai1e1:bi2ee").is_ok(), "sorted keys are fine");
        // A key that is not a byte string at all.
        assert_eq!(decode(b"di1ei2ee").err(), Some(DecodeError::Malformed));
    }

    #[test]
    fn nothing_here_can_be_made_to_run_away_with_the_stack_or_the_heap() {
        // Every bound, exercised. Each of these arrives unsolicited from a
        // stranger, so each has to end in a refusal rather than in work.
        let deep = {
            let mut v = b"l".repeat(MAX_DEPTH + 4);
            v.extend(b"e".repeat(MAX_DEPTH + 4));
            v
        };
        assert_eq!(
            decode(&deep).err(),
            Some(DecodeError::TooBig),
            "deep nesting"
        );

        // A length header that promises far more than the datagram holds.
        assert_eq!(decode(b"999999999:x").err(), Some(DecodeError::TooBig));
        // ...and one within the cap but still longer than the input.
        assert_eq!(decode(b"100:short").err(), Some(DecodeError::Truncated));
        // A length header long enough to be an attack on the length parser.
        assert_eq!(
            decode(b"11111111111111111111:x").err(),
            Some(DecodeError::TooBig)
        );
        // An integer body long enough to be the same.
        let long_int = [b"i".as_slice(), &b"9".repeat(64), b"e"].concat();
        assert_eq!(decode(&long_int).err(), Some(DecodeError::TooBig));

        let many = {
            let mut v = b"l".to_vec();
            v.extend(b"i1e".repeat(MAX_ITEMS + 1));
            v.extend(b"e");
            v
        };
        assert_eq!(decode(&many).err(), Some(DecodeError::TooBig), "item count");
    }

    #[test]
    fn a_value_that_does_not_use_the_whole_datagram_is_refused() {
        // Trailing bytes are how one datagram is made to look like two
        // different messages to two different readers.
        assert_eq!(decode(b"i1ei2e").err(), Some(DecodeError::TrailingBytes));
        assert_eq!(decode(b"3:abcx").err(), Some(DecodeError::TrailingBytes));
        assert_eq!(decode(b"").err(), Some(DecodeError::Truncated));
    }

    #[test]
    fn every_truncation_of_a_real_message_is_refused_and_none_of_them_panics() {
        // The sweep that matters for a UDP parser: a datagram can be cut at
        // any byte, and none of those cuts may panic or be mistaken for a
        // complete message.
        let full = encode(&dict([
            (
                b"a",
                dict([
                    (b"id", bytes("abcdefghij0123456789")),
                    (b"target", bytes("x")),
                ]),
            ),
            (b"q", bytes("find_node")),
            (b"t", bytes("aa")),
            (b"y", bytes("q")),
        ]));
        assert!(decode(&full).is_ok(), "the whole thing must parse");
        for cut in 0..full.len() {
            assert!(
                decode(&full[..cut]).is_err(),
                "a message cut at {cut} of {} was accepted",
                full.len()
            );
        }
        // And every single-byte corruption either parses to something else or
        // is refused -- but never panics. This is the loop that would find an
        // index-out-of-bounds.
        for i in 0..full.len() {
            for flip in [0x00u8, 0x01, 0x7f, 0xff] {
                let mut bad = full.clone();
                bad[i] ^= flip;
                let _ = decode(&bad);
            }
        }
    }

    #[test]
    fn the_accessors_answer_none_rather_than_guessing() {
        let v = dict([(b"n", Value::Int(7))]);
        assert_eq!(v.get(b"n").and_then(Value::as_int), Some(7));
        assert_eq!(v.get(b"n").and_then(Value::as_bytes), None);
        assert_eq!(v.get(b"missing"), None);
        assert_eq!(Value::Int(1).get(b"n"), None, "a non-dict has no keys");
        assert_eq!(Value::Int(1).as_list(), None);
        assert_eq!(bytes("x").as_dict(), None);
    }
}
