// SPDX-License-Identifier: Apache-2.0
//! DSSE v1 Pre-Authentication Encoding: source-only research component.
//! No signature checks, model quality, trust decisions, provider calls, or
//! production authority. The existing Python implementation remains canonical.
//! Protocol: https://github.com/secure-systems-lab/dsse/blob/master/protocol.md

use std::fmt::{Display, Formatter};

/// A local capacity guard, not a limit from the DSSE specification.
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// A local capacity guard, not a limit from the DSSE specification.
pub const MAX_TYPE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    EmptyPayloadType,
    TypeTooLarge,
    PayloadTooLarge,
    LengthOverflow,
}

impl Display for WireError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::EmptyPayloadType => "payload_type must be non-empty",
            Self::TypeTooLarge => "payload_type exceeds local byte limit",
            Self::PayloadTooLarge => "payload exceeds local byte limit",
            Self::LengthOverflow => "PAE output length overflow",
        };
        f.write_str(message)
    }
}

impl std::error::Error for WireError {}

/// Byte-identical to the SZL Python PAE implementation on admitted inputs.
/// The two length fields are ASCII decimal over UTF-8 type and raw payload.
pub fn pae(payload_type: &str, payload: &[u8]) -> Result<Vec<u8>, WireError> {
    let kind = payload_type.as_bytes();
    if kind.is_empty() {
        return Err(WireError::EmptyPayloadType);
    }
    if kind.len() > MAX_TYPE_BYTES {
        return Err(WireError::TypeTooLarge);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(WireError::PayloadTooLarge);
    }

    let kind_len = kind.len().to_string();
    let body_len = payload.len().to_string();
    let capacity = b"DSSEv1 "
        .len()
        .checked_add(kind_len.len())
        .and_then(|v| v.checked_add(1))
        .and_then(|v| v.checked_add(kind.len()))
        .and_then(|v| v.checked_add(1))
        .and_then(|v| v.checked_add(body_len.len()))
        .and_then(|v| v.checked_add(1))
        .and_then(|v| v.checked_add(payload.len()))
        .ok_or(WireError::LengthOverflow)?;

    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(b"DSSEv1 ");
    output.extend_from_slice(kind_len.as_bytes());
    output.push(b' ');
    output.extend_from_slice(kind);
    output.push(b' ');
    output.extend_from_slice(body_len.as_bytes());
    output.push(b' ');
    output.extend_from_slice(payload);
    debug_assert_eq!(output.len(), capacity);
    Ok(output)
}

#[cfg(feature = "python")]
mod python_api {
    use super::pae;
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;
    use pyo3::types::PyBytes;

    #[pyfunction(name = "pae")]
    fn python_pae<'py>(
        py: Python<'py>,
        payload_type: &str,
        payload: &Bound<'_, PyBytes>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let result = pae(payload_type, payload.as_bytes())
            .map_err(|error| PyValueError::new_err(error.to_string()))?;
        Ok(PyBytes::new(py, &result))
    }

    #[pymodule]
    fn szl_receipt_wire(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(python_pae, m)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_protocol_vector() {
        assert_eq!(
            pae("http://example.com/HelloWorld", b"hello world").unwrap(),
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
    }

    #[test]
    fn empty_payload_is_distinct_from_empty_type() {
        assert_eq!(
            pae("application/x-test", b"").unwrap(),
            b"DSSEv1 18 application/x-test 0 "
        );
        assert_eq!(pae("", b"a"), Err(WireError::EmptyPayloadType));
    }

    #[test]
    fn unicode_type_length_is_in_utf8_bytes() {
        assert_eq!(
            pae("text/é", &[0xcf, 0x80]).unwrap(),
            b"DSSEv1 7 text/\xc3\xa9 2 \xcf\x80"
        );
    }

    #[test]
    fn binary_payload_preserves_zero_and_non_utf8() {
        assert_eq!(
            pae("application/x-test", &[0, 255, 32, 13, 10]).unwrap(),
            b"DSSEv1 18 application/x-test 5 \x00\xff \r\n"
        );
    }

    #[test]
    fn oversized_inputs_refuse() {
        assert_eq!(
            pae("application/x-test", &vec![0; MAX_PAYLOAD_BYTES + 1]),
            Err(WireError::PayloadTooLarge)
        );
        assert_eq!(
            pae(&"x".repeat(MAX_TYPE_BYTES + 1), b""),
            Err(WireError::TypeTooLarge)
        );
    }

    #[test]
    fn encoded_length_is_exact_no_extra_delimiters() {
        let result = pae("x", b"y").unwrap();
        assert_eq!(result, b"DSSEv1 1 x 1 y");
        assert_eq!(result.len(), 14);
    }
}
