//! QUIC connection transport parameters
//!
//! The `TransportParameters` type is used to represent the transport parameters
//! negotiated by peers while establishing a QUIC connection. This process
//! happens as part of the establishment of the TLS session. As such, the types
//! contained in this modules should generally only be referred to by custom
//! implementations of the `crypto::Session` trait.

use std::{
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use bytes::{Buf, BufMut};
use rand::{Rng, RngExt, seq::SliceRandom as _};
use thiserror::Error;

use crate::{
    LOC_CID_COUNT, MAX_CID_SIZE, MAX_STREAM_COUNT, RESET_TOKEN_SIZE, ResetToken, Side,
    TIMER_GRANULARITY, TransportError, VarInt,
    cid_generator::ConnectionIdGenerator,
    cid_queue::CidQueue,
    coding::{BufExt, BufMutExt, UnexpectedEnd},
    config::{EndpointConfig, ServerConfig, TransportConfig},
    shared::ConnectionId,
};

/// A single entry in a user-specified transport parameter list.
#[derive(Debug, Clone)]
pub enum TransportParameterKind {
    /// Emit a standard, typed parameter by its well-known ID.
    ///
    /// The value is taken from the corresponding field on the
    /// [`TransportParameters`] struct (populated from [`TransportConfig`] and
    /// [`EndpointConfig`] as usual).  If the field's value equals the protocol
    /// default (i.e. would not normally be sent), the parameter is omitted —
    /// matching the behaviour of the built-in serializer.
    Known(TransportParameterId),

    /// Emit a GREASE transport parameter.
    ///
    /// A random reserved ID of the form `31·N + 27` with a random 1–8 byte
    /// payload is generated once per connection and written here.
    Grease,

    /// Emit a custom/unknown parameter with a raw byte value.
    Custom {
        /// Parameter ID — any QUIC varint value (≤ 2^62 − 1).
        id: u64,
        /// Raw bytes for the value field.
        value: Vec<u8>,
    },

    /// Emit the `version_information` transport parameter (ID `0x11`).
    ///
    /// Defined in RFC 9368 (QUIC Version Negotiation).  The wire format is a
    /// sequence of big-endian `u32` QUIC version numbers: the chosen version
    /// followed by the available versions list.
    ///
    /// Any [`VersionEntry::Grease`] items in `available` are replaced by a
    /// freshly-generated GREASE version number at connection time.
    VersionInformation(VersionInformation),
}

/// The `version_information` transport parameter value (TP ID `0x11`).
///
/// # Wire format
/// `[chosen: u32be, avail_0: u32be, avail_1: u32be, …]`
#[derive(Debug, Clone)]
pub struct VersionInformation {
    /// The QUIC version the endpoint has chosen for this connection.
    /// QUIC v1 (RFC 9000) = `1`.
    pub chosen_version: u32,
    /// Available versions advertised by the endpoint.
    pub available: Vec<VersionEntry>,
}

/// A single entry in the `version_information` available-versions list.
#[derive(Debug, Clone)]
pub enum VersionEntry {
    /// A real QUIC version number (big-endian `u32`).
    Real(u32),
    /// A GREASE version number, generated at connection time.
    ///
    /// Format: `0xXaXaXaXa` where each byte has the low nibble forced to `0x0a`
    /// and the high nibble is random (RFC 9368 §3).
    Grease,
}

/// Configures which transport parameters are emitted and in what order.
///
/// Pass this to [`TransportConfig::transport_parameter_config`] to control
/// which transport parameters are emitted.
///
/// - If `shuffle` is `true`, the wire order is randomised per-connection with a
///   Fisher-Yates shuffle.
/// - If `shuffle` is `false`, parameters are written in exactly the order given.
#[derive(Debug, Clone)]
pub struct TransportParameterConfig {
    /// The parameter kinds to emit, in the order they will be written (or shuffled from).
    pub entries: Arc<Vec<TransportParameterKind>>,
    /// Whether to apply a per-connection Fisher-Yates shuffle to the entries.
    pub shuffle: bool,
}

impl TransportParameterConfig {
    /// Create from a list of parameter kinds with an explicit shuffle setting.
    ///
    /// Pass `shuffle: true` for per-connection random ordering.
    /// Pass `shuffle: false` for a fixed, deterministic wire order.
    pub fn new(entries: Vec<TransportParameterKind>, shuffle: bool) -> Self {
        Self {
            entries: Arc::new(entries),
            shuffle,
        }
    }
}

// Apply a given macro to a list of all the transport parameters having integer types, along with
// their codes and default values. Using this helps us avoid error-prone duplication of the
// contained information across decoding, encoding, and the `Default` impl. Whenever we want to do
// something with transport parameters, we'll handle the bulk of cases by writing a macro that
// takes a list of arguments in this form, then passing it to this macro.
macro_rules! apply_params {
    ($macro:ident) => {
        $macro! {
            // #[doc] name (id) = default,
            /// Milliseconds, disabled if zero
            max_idle_timeout(MaxIdleTimeout) = 0,
            /// Limits the size of UDP payloads that the endpoint is willing to receive
            max_udp_payload_size(MaxUdpPayloadSize) = 65527,

            /// Initial value for the maximum amount of data that can be sent on the connection
            initial_max_data(InitialMaxData) = 0,
            /// Initial flow control limit for locally-initiated bidirectional streams
            initial_max_stream_data_bidi_local(InitialMaxStreamDataBidiLocal) = 0,
            /// Initial flow control limit for peer-initiated bidirectional streams
            initial_max_stream_data_bidi_remote(InitialMaxStreamDataBidiRemote) = 0,
            /// Initial flow control limit for unidirectional streams
            initial_max_stream_data_uni(InitialMaxStreamDataUni) = 0,

            /// Initial maximum number of bidirectional streams the peer may initiate
            initial_max_streams_bidi(InitialMaxStreamsBidi) = 0,
            /// Initial maximum number of unidirectional streams the peer may initiate
            initial_max_streams_uni(InitialMaxStreamsUni) = 0,

            /// Exponent used to decode the ACK Delay field in the ACK frame
            ack_delay_exponent(AckDelayExponent) = 3,
            /// Maximum amount of time in milliseconds by which the endpoint will delay sending
            /// acknowledgments
            max_ack_delay(MaxAckDelay) = 25,
            /// Maximum number of connection IDs from the peer that an endpoint is willing to store
            active_connection_id_limit(ActiveConnectionIdLimit) = 2,
        }
    };
}

macro_rules! make_struct {
    {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
        /// Transport parameters used to negotiate connection-level preferences between peers
        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct TransportParameters {
            $($(#[$doc])* pub(crate) $name : VarInt,)*

            /// Does the endpoint support active connection migration
            pub(crate) disable_active_migration: bool,
            /// Maximum size for datagram frames
            pub(crate) max_datagram_frame_size: Option<VarInt>,
            /// The value that the endpoint included in the Source Connection ID field of the first
            /// Initial packet it sends for the connection
            pub(crate) initial_src_cid: Option<ConnectionId>,
            /// The endpoint is willing to receive QUIC packets containing any value for the fixed
            /// bit
            pub(crate) grease_quic_bit: bool,

            /// Minimum amount of time in microseconds by which the endpoint is able to delay
            /// sending acknowledgments
            ///
            /// If a value is provided, it implies that the endpoint supports QUIC Acknowledgement
            /// Frequency
            pub(crate) min_ack_delay: Option<VarInt>,

            // Server-only
            /// The value of the Destination Connection ID field from the first Initial packet sent
            /// by the client
            pub(crate) original_dst_cid: Option<ConnectionId>,
            /// The value that the server included in the Source Connection ID field of a Retry
            /// packet
            pub(crate) retry_src_cid: Option<ConnectionId>,
            /// Token used by the client to verify a stateless reset from the server
            pub(crate) stateless_reset_token: Option<ResetToken>,
            /// The server's preferred address for communication after handshake completion
            pub(crate) preferred_address: Option<PreferredAddress>,
            /// The randomly generated reserved transport parameter to sustain future extensibility
            /// of transport parameter extensions.
            /// When present, it is included during serialization but ignored during deserialization.
            pub(crate) grease_transport_parameter: Option<ReservedTransportParameter>,

            /// Ordered list of entries to write during serialisation.
            ///
            /// `Some(_)` — use exactly this list (deterministic-order mode).
            /// `None`    — receiver-side `TransportParameters`; `write()` falls back to the
            ///             identity order of `TransportParameterId::SUPPORTED`.
            pub(crate) write_entries: Option<Vec<WriteEntry>>,
        }

        // We deliberately don't implement the `Default` trait, since that would be public, and
        // downstream crates should never construct `TransportParameters` except by decoding those
        // supplied by a peer.
        impl TransportParameters {
            /// Standard defaults, used if the peer does not supply a given parameter.
            pub(crate) fn default() -> Self {
                Self {
                    $($name: VarInt::from_u32($default),)*

                    disable_active_migration: false,
                    max_datagram_frame_size: None,
                    initial_src_cid: None,
                    grease_quic_bit: false,
                    min_ack_delay: None,

                    original_dst_cid: None,
                    retry_src_cid: None,
                    stateless_reset_token: None,
                    preferred_address: None,
                    grease_transport_parameter: None,
                    write_entries: None,
                }
            }
        }
    }
}

/// A resolved, per-connection serialisation entry.
///
/// Built once in [`TransportParameters::new`] so that GREASE values are
/// generated at connection time and stable across retransmits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WriteEntry {
    /// A known, typed parameter — value read from the struct fields.
    Known(TransportParameterId),
    /// A GREASE reserved parameter with pre-generated ID and payload.
    Grease(ReservedTransportParameter),
    /// A custom/unknown parameter with a verbatim byte value.
    Custom { id: u64, value: Vec<u8> },
    /// The `version_information` transport parameter (ID `0x11`).
    ///
    /// All GREASE version entries have been resolved to concrete `u32` values
    /// at the time this entry is created.
    VersionInformation {
        chosen_version: u32,
        available: Vec<u32>,
    },
}

/// Generate a GREASE QUIC version number.
///
/// Format: `0xXaXaXaXa` — each byte has its low nibble forced to `0x0a` and
/// its high nibble randomised (RFC 9368 §3).
fn grease_quic_version(rng: &mut impl Rng) -> u32 {
    let mut bytes = [0u8; 4];
    rng.fill(&mut bytes);
    u32::from_be_bytes(bytes.map(|b| (b & 0xf0) | 0x0a))
}

apply_params!(make_struct);

impl TransportParameters {
    pub(crate) fn new(
        config: &TransportConfig,
        endpoint_config: &EndpointConfig,
        cid_gen: &dyn ConnectionIdGenerator,
        initial_src_cid: ConnectionId,
        server_config: Option<&ServerConfig>,
        rng: &mut impl Rng,
    ) -> Self {
        let write_entries = match &config.transport_parameter_config {
            Some(tp_config) => {
                // Resolve user-specified kinds → WriteEntry.
                let mut entries: Vec<WriteEntry> = tp_config
                    .entries
                    .iter()
                    .map(|kind| match kind {
                        TransportParameterKind::Known(id) => WriteEntry::Known(*id),
                        TransportParameterKind::Grease => {
                            WriteEntry::Grease(ReservedTransportParameter::random(rng))
                        }
                        TransportParameterKind::Custom { id, value } => WriteEntry::Custom {
                            id: *id,
                            value: value.clone(),
                        },
                        TransportParameterKind::VersionInformation(vi) => {
                            let available = vi
                                .available
                                .iter()
                                .map(|entry| match entry {
                                    VersionEntry::Real(v) => *v,
                                    VersionEntry::Grease => grease_quic_version(rng),
                                })
                                .collect();
                            WriteEntry::VersionInformation {
                                chosen_version: vi.chosen_version,
                                available,
                            }
                        }
                    })
                    .collect();
                if tp_config.shuffle {
                    entries.shuffle(rng);
                }
                entries
            }
            None => {
                // Default path: random shuffle of all known IDs with one GREASE entry.
                let grease = ReservedTransportParameter::random(rng);
                let mut entries: Vec<WriteEntry> = TransportParameterId::SUPPORTED
                    .iter()
                    .map(|&id| WriteEntry::Known(id))
                    .collect();
                entries.shuffle(rng);
                let pos = rng.random_range(0..=entries.len());
                entries.insert(pos, WriteEntry::Grease(grease));
                entries
            }
        };

        Self {
            initial_src_cid: Some(initial_src_cid),
            initial_max_streams_bidi: config.max_concurrent_bidi_streams,
            initial_max_streams_uni: config.max_concurrent_uni_streams,
            initial_max_data: config.receive_window,
            initial_max_stream_data_bidi_local: config.stream_receive_window,
            initial_max_stream_data_bidi_remote: config.stream_receive_window,
            initial_max_stream_data_uni: config.stream_receive_window,
            max_udp_payload_size: endpoint_config.max_udp_payload_size,
            max_idle_timeout: config.max_idle_timeout.unwrap_or(VarInt(0)),
            disable_active_migration: server_config.is_some_and(|c| !c.migration),
            active_connection_id_limit: if cid_gen.cid_len() == 0 {
                2 // i.e. default, i.e. unsent
            } else {
                CidQueue::LEN as u32
            }
            .into(),
            max_datagram_frame_size: config
                .datagram_receive_buffer_size
                .map(|x| VarInt::try_from(x as u64).unwrap_or(VarInt::MAX)),
            grease_quic_bit: endpoint_config.grease_quic_bit,
            min_ack_delay: Some(
                VarInt::from_u64(u64::try_from(TIMER_GRANULARITY.as_micros()).unwrap()).unwrap(),
            ),
            grease_transport_parameter: None, // embedded in write_entries
            write_entries: Some(write_entries),
            ..Self::default()
        }
    }

    /// Check that these parameters are legal when resuming from
    /// certain cached parameters
    pub(crate) fn validate_resumption_from(&self, cached: &Self) -> Result<(), TransportError> {
        if cached.active_connection_id_limit > self.active_connection_id_limit
            || cached.initial_max_data > self.initial_max_data
            || cached.initial_max_stream_data_bidi_local > self.initial_max_stream_data_bidi_local
            || cached.initial_max_stream_data_bidi_remote > self.initial_max_stream_data_bidi_remote
            || cached.initial_max_stream_data_uni > self.initial_max_stream_data_uni
            || cached.initial_max_streams_bidi > self.initial_max_streams_bidi
            || cached.initial_max_streams_uni > self.initial_max_streams_uni
            || cached.max_datagram_frame_size > self.max_datagram_frame_size
            || cached.grease_quic_bit && !self.grease_quic_bit
        {
            return Err(TransportError::PROTOCOL_VIOLATION(
                "0-RTT accepted with incompatible transport parameters",
            ));
        }
        Ok(())
    }

    /// Maximum number of CIDs to issue to this peer
    ///
    /// Consider both a) the active_connection_id_limit from the other end; and
    /// b) LOC_CID_COUNT used locally
    pub(crate) fn issue_cids_limit(&self) -> u64 {
        self.active_connection_id_limit.0.min(LOC_CID_COUNT)
    }
}

/// A server's preferred address
///
/// This is communicated as a transport parameter during TLS session establishment.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct PreferredAddress {
    pub(crate) address_v4: Option<SocketAddrV4>,
    pub(crate) address_v6: Option<SocketAddrV6>,
    pub(crate) connection_id: ConnectionId,
    pub(crate) stateless_reset_token: ResetToken,
}

impl PreferredAddress {
    fn wire_size(&self) -> u16 {
        4 + 2 + 16 + 2 + 1 + self.connection_id.len() as u16 + 16
    }

    fn write<W: BufMut>(&self, w: &mut W) {
        w.write(self.address_v4.map_or(Ipv4Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v4.map_or(0, |x| x.port()));
        w.write(self.address_v6.map_or(Ipv6Addr::UNSPECIFIED, |x| *x.ip()));
        w.write::<u16>(self.address_v6.map_or(0, |x| x.port()));
        w.write::<u8>(self.connection_id.len() as u8);
        w.put_slice(&self.connection_id);
        w.put_slice(&self.stateless_reset_token);
    }

    fn read<R: Buf>(r: &mut R) -> Result<Self, Error> {
        let ip_v4 = r.get::<Ipv4Addr>()?;
        let port_v4 = r.get::<u16>()?;
        let ip_v6 = r.get::<Ipv6Addr>()?;
        let port_v6 = r.get::<u16>()?;
        let cid_len = r.get::<u8>()?;
        if r.remaining() < cid_len as usize || cid_len > MAX_CID_SIZE as u8 {
            return Err(Error::Malformed);
        }
        let mut stage = [0; MAX_CID_SIZE];
        r.copy_to_slice(&mut stage[0..cid_len as usize]);
        let cid = ConnectionId::new(&stage[0..cid_len as usize]);
        if r.remaining() < 16 {
            return Err(Error::Malformed);
        }
        let mut token = [0; RESET_TOKEN_SIZE];
        r.copy_to_slice(&mut token);
        let address_v4 = if ip_v4.is_unspecified() && port_v4 == 0 {
            None
        } else {
            Some(SocketAddrV4::new(ip_v4, port_v4))
        };
        let address_v6 = if ip_v6.is_unspecified() && port_v6 == 0 {
            None
        } else {
            Some(SocketAddrV6::new(ip_v6, port_v6, 0, 0))
        };
        if address_v4.is_none() && address_v6.is_none() {
            return Err(Error::IllegalValue);
        }
        Ok(Self {
            address_v4,
            address_v6,
            connection_id: cid,
            stateless_reset_token: token.into(),
        })
    }
}

/// Errors encountered while decoding `TransportParameters`
#[derive(Debug, Copy, Clone, Eq, PartialEq, Error)]
pub enum Error {
    /// Parameters that are semantically invalid
    #[error("parameter had illegal value")]
    IllegalValue,
    /// Catch-all error for problems while decoding transport parameters
    #[error("parameters were malformed")]
    Malformed,
}

impl From<Error> for TransportError {
    fn from(e: Error) -> Self {
        match e {
            Error::IllegalValue => Self::TRANSPORT_PARAMETER_ERROR("illegal value"),
            Error::Malformed => Self::TRANSPORT_PARAMETER_ERROR("malformed"),
        }
    }
}

impl From<UnexpectedEnd> for Error {
    fn from(_: UnexpectedEnd) -> Self {
        Self::Malformed
    }
}

impl TransportParameters {
    /// Encode `TransportParameters` into buffer
    pub fn write<W: BufMut>(&self, w: &mut W) {
        // Collect the entries to iterate over.  For receiver-side params
        // (write_entries == None) we fall back to the identity order of
        // SUPPORTED so that unit tests constructing TransportParameters
        // directly still work.
        let fallback: Vec<WriteEntry> = TransportParameterId::SUPPORTED
            .iter()
            .map(|&id| WriteEntry::Known(id))
            .collect();
        let entries = match &self.write_entries {
            Some(e) => e.as_slice(),
            None => fallback.as_slice(),
        };

        for entry in entries {
            match entry {
                WriteEntry::Grease(param) => {
                    param.write(w);
                }
                WriteEntry::Custom { id, value } => {
                    w.write_var(*id);
                    w.write_var(value.len() as u64);
                    w.put_slice(value);
                }
                WriteEntry::VersionInformation {
                    chosen_version,
                    available,
                } => {
                    // TP ID 0x11 (RFC 9368).
                    // Value: chosen_version (u32be) followed by each available
                    // version (u32be).  Total length = 4 * (1 + available.len()).
                    const TP_VERSION_INFORMATION: u64 = 0x11;
                    let value_len = 4u64 * (1 + available.len() as u64);
                    w.write_var(TP_VERSION_INFORMATION);
                    w.write_var(value_len);
                    w.put_u32(*chosen_version);
                    for v in available {
                        w.put_u32(*v);
                    }
                }
                WriteEntry::Known(id) => {
                    self.write_known(*id, w);
                }
            }
        }

        // Legacy: if grease_transport_parameter is set (receiver-side default
        // path that still uses the old field), emit it too.
        if let Some(param) = self.grease_transport_parameter {
            param.write(w);
        }
    }

    fn write_known<W: BufMut>(&self, id: TransportParameterId, w: &mut W) {
        match id {
            TransportParameterId::ReservedTransportParameter => {
                // Handled via WriteEntry::Grease; skip the legacy slot here.
            }
            TransportParameterId::StatelessResetToken => {
                if let Some(ref x) = self.stateless_reset_token {
                    w.write_var(id as u64);
                    w.write_var(16);
                    w.put_slice(x);
                }
            }
            TransportParameterId::DisableActiveMigration => {
                if self.disable_active_migration {
                    w.write_var(id as u64);
                    w.write_var(0);
                }
            }
            TransportParameterId::MaxDatagramFrameSize => {
                if let Some(x) = self.max_datagram_frame_size {
                    w.write_var(id as u64);
                    w.write_var(x.size() as u64);
                    w.write(x);
                }
            }
            TransportParameterId::PreferredAddress => {
                if let Some(ref x) = self.preferred_address {
                    w.write_var(id as u64);
                    w.write_var(x.wire_size() as u64);
                    x.write(w);
                }
            }
            TransportParameterId::OriginalDestinationConnectionId => {
                if let Some(ref cid) = self.original_dst_cid {
                    w.write_var(id as u64);
                    w.write_var(cid.len() as u64);
                    w.put_slice(cid);
                }
            }
            TransportParameterId::InitialSourceConnectionId => {
                if let Some(ref cid) = self.initial_src_cid {
                    w.write_var(id as u64);
                    w.write_var(cid.len() as u64);
                    w.put_slice(cid);
                }
            }
            TransportParameterId::RetrySourceConnectionId => {
                if let Some(ref cid) = self.retry_src_cid {
                    w.write_var(id as u64);
                    w.write_var(cid.len() as u64);
                    w.put_slice(cid);
                }
            }
            TransportParameterId::GreaseQuicBit => {
                if self.grease_quic_bit {
                    w.write_var(id as u64);
                    w.write_var(0);
                }
            }
            TransportParameterId::MinAckDelayDraft07 => {
                if let Some(x) = self.min_ack_delay {
                    w.write_var(id as u64);
                    w.write_var(x.size() as u64);
                    w.write(x);
                }
            }
            id => {
                macro_rules! write_params {
                    {$($(#[$doc:meta])* $name:ident ($pid:ident) = $default:expr,)*} => {
                        match id {
                            $(TransportParameterId::$pid => {
                                if self.$name.0 != $default {
                                    w.write_var(id as u64);
                                    w.write(VarInt::try_from(self.$name.size()).unwrap());
                                    w.write(self.$name);
                                }
                            })*,
                            _ => {
                                unimplemented!("Missing implementation of write for transport parameter with code {id:?}");
                            }
                        }
                    }
                }
                apply_params!(write_params);
            }
        }
    }

    /// Decode `TransportParameters` from buffer
    pub fn read<R: Buf>(side: Side, r: &mut R) -> Result<Self, Error> {
        // Initialize to protocol-specified defaults
        let mut params = Self::default();

        // State to check for duplicate transport parameters.
        macro_rules! param_state {
            {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {{
                struct ParamState {
                    $($name: bool,)*
                }

                ParamState {
                    $($name: false,)*
                }
            }}
        }
        let mut got = apply_params!(param_state);

        while r.has_remaining() {
            let id = r.get_var()?;
            let len = r.get_var()?;
            if (r.remaining() as u64) < len {
                return Err(Error::Malformed);
            }
            let len = len as usize;
            let Ok(id) = TransportParameterId::try_from(id) else {
                // unknown transport parameters are ignored
                r.advance(len);
                continue;
            };

            match id {
                TransportParameterId::OriginalDestinationConnectionId => {
                    decode_cid(len, &mut params.original_dst_cid, r)?
                }
                TransportParameterId::StatelessResetToken => {
                    if len != 16 || params.stateless_reset_token.is_some() {
                        return Err(Error::Malformed);
                    }
                    let mut tok = [0; RESET_TOKEN_SIZE];
                    r.copy_to_slice(&mut tok);
                    params.stateless_reset_token = Some(tok.into());
                }
                TransportParameterId::DisableActiveMigration => {
                    if len != 0 || params.disable_active_migration {
                        return Err(Error::Malformed);
                    }
                    params.disable_active_migration = true;
                }
                TransportParameterId::PreferredAddress => {
                    if params.preferred_address.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.preferred_address = Some(PreferredAddress::read(&mut r.take(len))?);
                }
                TransportParameterId::InitialSourceConnectionId => {
                    decode_cid(len, &mut params.initial_src_cid, r)?
                }
                TransportParameterId::RetrySourceConnectionId => {
                    decode_cid(len, &mut params.retry_src_cid, r)?
                }
                TransportParameterId::MaxDatagramFrameSize => {
                    if len > 8 || params.max_datagram_frame_size.is_some() {
                        return Err(Error::Malformed);
                    }
                    params.max_datagram_frame_size = Some(r.get()?);
                }
                TransportParameterId::GreaseQuicBit => match len {
                    0 => params.grease_quic_bit = true,
                    _ => return Err(Error::Malformed),
                },
                TransportParameterId::MinAckDelayDraft07 => params.min_ack_delay = Some(r.get()?),
                _ => {
                    macro_rules! parse {
                        {$($(#[$doc:meta])* $name:ident ($id:ident) = $default:expr,)*} => {
                            match id {
                                $(TransportParameterId::$id => {
                                    let value = r.get::<VarInt>()?;
                                    if len != value.size() || got.$name { return Err(Error::Malformed); }
                                    params.$name = value.into();
                                    got.$name = true;
                                })*
                                _ => r.advance(len),
                            }
                        }
                    }
                    apply_params!(parse);
                }
            }
        }

        // Semantic validation

        // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.26.1
        if params.ack_delay_exponent.0 > 20
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.28.1
            || params.max_ack_delay.0 >= 1 << 14
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-6.2.1
            || params.active_connection_id_limit.0 < 2
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.10.1
            || params.max_udp_payload_size.0 < 1200
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-4.6-2
            || params.initial_max_streams_bidi.0 > MAX_STREAM_COUNT
            || params.initial_max_streams_uni.0 > MAX_STREAM_COUNT
            // https://www.ietf.org/archive/id/draft-ietf-quic-ack-frequency-08.html#section-3-4
            || params.min_ack_delay.is_some_and(|min_ack_delay| {
                // min_ack_delay uses microseconds, whereas max_ack_delay uses milliseconds
                min_ack_delay.0 > params.max_ack_delay.0 * 1_000
            })
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-8
            || (side.is_server()
                && (params.original_dst_cid.is_some()
                    || params.preferred_address.is_some()
                    || params.retry_src_cid.is_some()
                    || params.stateless_reset_token.is_some()))
            // https://www.rfc-editor.org/rfc/rfc9000.html#section-18.2-4.38.1
            || params
                .preferred_address.is_some_and(|x| x.connection_id.is_empty())
        {
            return Err(Error::IllegalValue);
        }

        Ok(params)
    }
}

/// A reserved transport parameter.
///
/// It has an identifier of the form 31 * N + 27 for the integer value of N.
/// Such identifiers are reserved to exercise the requirement that unknown transport parameters be ignored.
/// The reserved transport parameter has no semantics and can carry arbitrary values.
/// It may be included in transport parameters sent to the peer, and should be ignored when received.
///
/// See spec: <https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1>
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub(crate) struct ReservedTransportParameter {
    /// The reserved identifier of the transport parameter
    id: VarInt,

    /// Buffer to store the parameter payload
    payload: [u8; Self::MAX_PAYLOAD_LEN],

    /// The number of bytes to include in the wire format from the `payload` buffer
    payload_len: usize,
}

impl ReservedTransportParameter {
    /// Generates a transport parameter with a random payload and a reserved ID.
    ///
    /// The implementation is inspired by quic-go and quiche:
    /// 1. <https://github.com/quic-go/quic-go/blob/3e0a67b2476e1819752f04d75968de042b197b56/internal/wire/transport_parameters.go#L338-L344>
    /// 2. <https://github.com/google/quiche/blob/cb1090b20c40e2f0815107857324e99acf6ec567/quiche/quic/core/crypto/transport_parameters.cc#L843-L860>
    fn random(rng: &mut impl Rng) -> Self {
        let id = Self::generate_reserved_id(rng);

        let payload_len = rng.random_range(0..Self::MAX_PAYLOAD_LEN);

        let payload = {
            let mut slice = [0u8; Self::MAX_PAYLOAD_LEN];
            rng.fill_bytes(&mut slice[..payload_len]);
            slice
        };

        Self {
            id,
            payload,
            payload_len,
        }
    }

    fn write(&self, w: &mut impl BufMut) {
        w.write_var(self.id.0);
        w.write_var(self.payload_len as u64);
        w.put_slice(&self.payload[..self.payload_len]);
    }

    /// Generates a random reserved identifier of the form `31 * N + 27`, as required by RFC 9000.
    /// Reserved transport parameter identifiers are used to test compliance with the requirement
    /// that unknown transport parameters must be ignored by peers.
    /// See: <https://www.rfc-editor.org/rfc/rfc9000.html#section-18.1> and <https://www.rfc-editor.org/rfc/rfc9000.html#section-22.3>
    fn generate_reserved_id(rng: &mut impl Rng) -> VarInt {
        let id = {
            let rand = rng.random_range(0u64..(1 << 62) - 27);
            let n = rand / 31;
            31 * n + 27
        };
        debug_assert!(
            id % 31 == 27,
            "generated id does not have the form of 31 * N + 27"
        );
        VarInt::from_u64(id).expect(
            "generated id does fit into range of allowed transport parameter IDs: [0; 2^62)",
        )
    }

    /// The maximum length of the payload to include as the parameter payload.
    /// This value is not a specification-imposed limit but is chosen to match
    /// the limit used by other implementations of QUIC, e.g., quic-go and quiche.
    const MAX_PAYLOAD_LEN: usize = 16;
}

/// Identifies a QUIC transport parameter by its wire ID.
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportParameterId {
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    OriginalDestinationConnectionId = 0x00,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    MaxIdleTimeout = 0x01,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    StatelessResetToken = 0x02,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    MaxUdpPayloadSize = 0x03,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    InitialMaxData = 0x04,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    InitialMaxStreamDataBidiLocal = 0x05,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    InitialMaxStreamDataBidiRemote = 0x06,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    InitialMaxStreamDataUni = 0x07,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    InitialMaxStreamsBidi = 0x08,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    InitialMaxStreamsUni = 0x09,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    AckDelayExponent = 0x0A,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    MaxAckDelay = 0x0B,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    DisableActiveMigration = 0x0C,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    PreferredAddress = 0x0D,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    ActiveConnectionIdLimit = 0x0E,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    InitialSourceConnectionId = 0x0F,
    /// <https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table>
    RetrySourceConnectionId = 0x10,

    /// Smallest possible ID of reserved transport parameter. <https://datatracker.ietf.org/doc/html/rfc9000#section-22.3>
    ReservedTransportParameter = 0x1B,

    /// <https://www.rfc-editor.org/rfc/rfc9221.html#section-3>
    MaxDatagramFrameSize = 0x20,

    /// <https://www.rfc-editor.org/rfc/rfc9287.html#section-3>
    GreaseQuicBit = 0x2AB2,

    /// <https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency#section-10.1>
    MinAckDelayDraft07 = 0xFF04DE1B,
}

impl TransportParameterId {
    /// Array with all supported transport parameter IDs
    const SUPPORTED: [Self; 21] = [
        Self::MaxIdleTimeout,
        Self::MaxUdpPayloadSize,
        Self::InitialMaxData,
        Self::InitialMaxStreamDataBidiLocal,
        Self::InitialMaxStreamDataBidiRemote,
        Self::InitialMaxStreamDataUni,
        Self::InitialMaxStreamsBidi,
        Self::InitialMaxStreamsUni,
        Self::AckDelayExponent,
        Self::MaxAckDelay,
        Self::ActiveConnectionIdLimit,
        Self::ReservedTransportParameter,
        Self::StatelessResetToken,
        Self::DisableActiveMigration,
        Self::MaxDatagramFrameSize,
        Self::PreferredAddress,
        Self::OriginalDestinationConnectionId,
        Self::InitialSourceConnectionId,
        Self::RetrySourceConnectionId,
        Self::GreaseQuicBit,
        Self::MinAckDelayDraft07,
    ];
}

impl PartialEq<u64> for TransportParameterId {
    fn eq(&self, other: &u64) -> bool {
        *other == (*self as u64)
    }
}

impl TryFrom<u64> for TransportParameterId {
    type Error = ();

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let param = match value {
            id if Self::MaxIdleTimeout == id => Self::MaxIdleTimeout,
            id if Self::MaxUdpPayloadSize == id => Self::MaxUdpPayloadSize,
            id if Self::InitialMaxData == id => Self::InitialMaxData,
            id if Self::InitialMaxStreamDataBidiLocal == id => Self::InitialMaxStreamDataBidiLocal,
            id if Self::InitialMaxStreamDataBidiRemote == id => {
                Self::InitialMaxStreamDataBidiRemote
            }
            id if Self::InitialMaxStreamDataUni == id => Self::InitialMaxStreamDataUni,
            id if Self::InitialMaxStreamsBidi == id => Self::InitialMaxStreamsBidi,
            id if Self::InitialMaxStreamsUni == id => Self::InitialMaxStreamsUni,
            id if Self::AckDelayExponent == id => Self::AckDelayExponent,
            id if Self::MaxAckDelay == id => Self::MaxAckDelay,
            id if Self::ActiveConnectionIdLimit == id => Self::ActiveConnectionIdLimit,
            id if Self::ReservedTransportParameter == id => Self::ReservedTransportParameter,
            id if Self::StatelessResetToken == id => Self::StatelessResetToken,
            id if Self::DisableActiveMigration == id => Self::DisableActiveMigration,
            id if Self::MaxDatagramFrameSize == id => Self::MaxDatagramFrameSize,
            id if Self::PreferredAddress == id => Self::PreferredAddress,
            id if Self::OriginalDestinationConnectionId == id => {
                Self::OriginalDestinationConnectionId
            }
            id if Self::InitialSourceConnectionId == id => Self::InitialSourceConnectionId,
            id if Self::RetrySourceConnectionId == id => Self::RetrySourceConnectionId,
            id if Self::GreaseQuicBit == id => Self::GreaseQuicBit,
            id if Self::MinAckDelayDraft07 == id => Self::MinAckDelayDraft07,
            _ => return Err(()),
        };
        Ok(param)
    }
}

fn decode_cid(len: usize, value: &mut Option<ConnectionId>, r: &mut impl Buf) -> Result<(), Error> {
    if len > MAX_CID_SIZE || value.is_some() || r.remaining() < len {
        return Err(Error::Malformed);
    }

    *value = Some(ConnectionId::from_buf(r, len));
    Ok(())
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use rand::TryRng;

    use super::*;

    #[test]
    fn coding() {
        let mut buf = Vec::new();
        let params = TransportParameters {
            initial_src_cid: Some(ConnectionId::new(&[])),
            original_dst_cid: Some(ConnectionId::new(&[])),
            initial_max_streams_bidi: 16u32.into(),
            initial_max_streams_uni: 16u32.into(),
            ack_delay_exponent: 2u32.into(),
            max_udp_payload_size: 1200u32.into(),
            preferred_address: Some(PreferredAddress {
                address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                address_v6: Some(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 24, 0, 0)),
                connection_id: ConnectionId::new(&[0x42]),
                stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
            }),
            grease_quic_bit: true,
            min_ack_delay: Some(2_000u32.into()),
            ..TransportParameters::default()
        };
        params.write(&mut buf);
        assert_eq!(
            TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap(),
            params
        );
    }

    #[test]
    fn reserved_transport_parameter_generate_reserved_id() {
        let mut rngs = [
            StepRng(0),
            StepRng(1),
            StepRng(27),
            StepRng(31),
            StepRng(u32::MAX as u64),
            StepRng(u32::MAX as u64 - 1),
            StepRng(u32::MAX as u64 + 1),
            StepRng(u32::MAX as u64 - 27),
            StepRng(u32::MAX as u64 + 27),
            StepRng(u32::MAX as u64 - 31),
            StepRng(u32::MAX as u64 + 31),
            StepRng(u64::MAX),
            StepRng(u64::MAX - 1),
            StepRng(u64::MAX - 27),
            StepRng(u64::MAX - 31),
            StepRng(1 << 62),
            StepRng((1 << 62) - 1),
            StepRng((1 << 62) + 1),
            StepRng((1 << 62) - 27),
            StepRng((1 << 62) + 27),
            StepRng((1 << 62) - 31),
            StepRng((1 << 62) + 31),
        ];
        for rng in &mut rngs {
            let id = ReservedTransportParameter::generate_reserved_id(rng);
            assert!(id.0 % 31 == 27)
        }
    }

    struct StepRng(u64);

    impl TryRng for StepRng {
        type Error = Infallible;

        #[inline]
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.next_u64() as u32)
        }

        #[inline]
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let res = self.0;
            self.0 = self.0.wrapping_add(1);
            Ok(res)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            let mut left = dst;
            while left.len() >= 8 {
                let (l, r) = left.split_at_mut(8);
                left = r;
                l.copy_from_slice(&self.next_u64().to_le_bytes());
            }
            let n = left.len();
            if n > 0 {
                left.copy_from_slice(&self.next_u32().to_le_bytes()[..n]);
            }

            Ok(())
        }
    }

    #[test]
    fn reserved_transport_parameter_ignored_when_read() {
        let mut buf = Vec::new();
        let reserved_parameter = ReservedTransportParameter::random(&mut rand::rng());
        assert!(reserved_parameter.payload_len < ReservedTransportParameter::MAX_PAYLOAD_LEN);
        assert!(reserved_parameter.id.0 % 31 == 27);

        reserved_parameter.write(&mut buf);
        assert!(!buf.is_empty());
        let read_params = TransportParameters::read(Side::Server, &mut buf.as_slice()).unwrap();
        assert_eq!(read_params, TransportParameters::default());
    }

    #[test]
    fn read_semantic_validation() {
        #[allow(clippy::type_complexity)]
        let illegal_params_builders: Vec<Box<dyn FnMut(&mut TransportParameters)>> = vec![
            Box::new(|t| {
                // This min_ack_delay is bigger than max_ack_delay!
                let min_ack_delay = t.max_ack_delay.0 * 1_000 + 1;
                t.min_ack_delay = Some(VarInt::from_u64(min_ack_delay).unwrap())
            }),
            Box::new(|t| {
                // Preferred address can only be sent by senders (and we are reading the transport
                // params as a client)
                t.preferred_address = Some(PreferredAddress {
                    address_v4: Some(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 42)),
                    address_v6: None,
                    connection_id: ConnectionId::new(&[]),
                    stateless_reset_token: [0xab; RESET_TOKEN_SIZE].into(),
                })
            }),
        ];

        for mut builder in illegal_params_builders {
            let mut buf = Vec::new();
            let mut params = TransportParameters::default();
            builder(&mut params);
            params.write(&mut buf);

            assert_eq!(
                TransportParameters::read(Side::Server, &mut buf.as_slice()),
                Err(Error::IllegalValue)
            );
        }
    }

    #[test]
    fn resumption_params_validation() {
        let high_limit = TransportParameters {
            initial_max_streams_uni: 32u32.into(),
            ..TransportParameters::default()
        };
        let low_limit = TransportParameters {
            initial_max_streams_uni: 16u32.into(),
            ..TransportParameters::default()
        };
        high_limit.validate_resumption_from(&low_limit).unwrap();
        low_limit.validate_resumption_from(&high_limit).unwrap_err();
    }

    // -- Tests for deterministic transport parameter ordering --

    /// Helper: build TransportParameters via `new()` with a given config.
    fn build_tp(config: &TransportConfig) -> TransportParameters {
        use crate::cid_generator::ConnectionIdGenerator;
        struct FixedLen;
        impl ConnectionIdGenerator for FixedLen {
            fn generate_cid(&mut self) -> ConnectionId {
                ConnectionId::new(&[0u8; 8])
            }
            fn cid_len(&self) -> usize {
                8
            }
            fn cid_lifetime(&self) -> Option<std::time::Duration> {
                None
            }
        }
        let ep = EndpointConfig::default();
        let mut rng = StepRng(42);
        TransportParameters::new(
            config,
            &ep,
            &FixedLen,
            ConnectionId::new(&[0u8; 8]),
            None,
            &mut rng,
        )
    }

    #[test]
    fn default_config_has_shuffled_entries_with_grease() {
        let config = TransportConfig::default();
        let tp = build_tp(&config);
        let entries = tp.write_entries.as_ref().unwrap();

        let known_count = entries
            .iter()
            .filter(|e| matches!(e, WriteEntry::Known(_)))
            .count();
        let grease_count = entries
            .iter()
            .filter(|e| matches!(e, WriteEntry::Grease(_)))
            .count();
        assert_eq!(known_count, TransportParameterId::SUPPORTED.len());
        assert_eq!(grease_count, 1);
    }

    #[test]
    fn deterministic_order_matches_config() {
        let mut config = TransportConfig::default();
        let order = vec![
            TransportParameterKind::Known(TransportParameterId::InitialMaxData),
            TransportParameterKind::Grease,
            TransportParameterKind::Known(TransportParameterId::MaxIdleTimeout),
            TransportParameterKind::Custom {
                id: 0x3127,
                value: vec![0xAB, 0xCD],
            },
        ];
        config.transport_parameter_config(TransportParameterConfig::new(order, false));
        let tp = build_tp(&config);
        let entries = tp.write_entries.as_ref().unwrap();

        assert_eq!(entries.len(), 4);
        assert!(matches!(
            entries[0],
            WriteEntry::Known(TransportParameterId::InitialMaxData)
        ));
        assert!(matches!(entries[1], WriteEntry::Grease(_)));
        assert!(matches!(
            entries[2],
            WriteEntry::Known(TransportParameterId::MaxIdleTimeout)
        ));
        match &entries[3] {
            WriteEntry::Custom { id, value } => {
                assert_eq!(*id, 0x3127);
                assert_eq!(value, &[0xAB, 0xCD]);
            }
            other => panic!("expected Custom, got {other:?}"),
        }
    }

    #[test]
    fn shuffled_config_entries_all_present() {
        let mut config = TransportConfig::default();
        let order = vec![
            TransportParameterKind::Known(TransportParameterId::InitialMaxData),
            TransportParameterKind::Grease,
            TransportParameterKind::Known(TransportParameterId::MaxIdleTimeout),
            TransportParameterKind::Custom {
                id: 0x3127,
                value: vec![0xAB, 0xCD],
            },
        ];
        config.transport_parameter_config(TransportParameterConfig::new(order, true));
        let tp = build_tp(&config);
        let entries = tp.write_entries.as_ref().unwrap();

        // Order is shuffled per-connection; assert the set, not the sequence.
        assert_eq!(entries.len(), 4);
        assert!(
            entries
                .iter()
                .any(|e| matches!(e, WriteEntry::Known(TransportParameterId::InitialMaxData)))
        );
        assert!(entries.iter().any(|e| matches!(e, WriteEntry::Grease(_))));
        assert!(
            entries
                .iter()
                .any(|e| matches!(e, WriteEntry::Known(TransportParameterId::MaxIdleTimeout)))
        );
        assert!(
            entries
                .iter()
                .any(|e| matches!(e, WriteEntry::Custom { id, value }
            if *id == 0x3127 && value == &[0xAB, 0xCD]))
        );
    }

    #[test]
    fn custom_entry_wire_format() {
        let mut config = TransportConfig::default();
        config.transport_parameter_config(TransportParameterConfig::new(
            vec![TransportParameterKind::Custom {
                id: 0x3127,
                value: vec![0x01, 0x02, 0x03],
            }],
            false,
        ));
        let tp = build_tp(&config);

        let mut buf = Vec::new();
        tp.write(&mut buf);

        assert!(
            buf.windows(6)
                .any(|w| w == [0x71, 0x27, 0x03, 0x01, 0x02, 0x03]),
            "custom parameter 0x3127 with value [01,02,03] not found in wire output: {buf:02x?}"
        );
    }

    #[test]
    fn deterministic_order_roundtrip() {
        let mut config = TransportConfig::default();
        config.transport_parameter_config(TransportParameterConfig::new(
            vec![
                TransportParameterKind::Known(TransportParameterId::InitialMaxStreamDataBidiLocal),
                TransportParameterKind::Known(TransportParameterId::InitialMaxData),
                TransportParameterKind::Known(TransportParameterId::InitialMaxStreamsBidi),
                TransportParameterKind::Known(TransportParameterId::InitialSourceConnectionId),
            ],
            false,
        ));
        let tp = build_tp(&config);

        let mut buf = Vec::new();
        tp.write(&mut buf);
        let decoded = TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap();

        assert_eq!(decoded.initial_max_data, tp.initial_max_data);
        assert_eq!(
            decoded.initial_max_streams_bidi,
            tp.initial_max_streams_bidi
        );
        assert_eq!(
            decoded.initial_max_stream_data_bidi_local,
            tp.initial_max_stream_data_bidi_local
        );
        assert_eq!(decoded.initial_src_cid, tp.initial_src_cid);
    }

    #[test]
    fn empty_config_writes_nothing() {
        let mut config = TransportConfig::default();
        config.transport_parameter_config(TransportParameterConfig::new(vec![], false));
        let tp = build_tp(&config);

        let mut buf = Vec::new();
        tp.write(&mut buf);
        assert!(buf.is_empty(), "expected empty wire output, got {buf:02x?}");
    }

    #[test]
    fn deterministic_grease_has_valid_id() {
        let mut config = TransportConfig::default();
        config.transport_parameter_config(TransportParameterConfig::new(
            vec![
                TransportParameterKind::Grease,
                TransportParameterKind::Grease,
            ],
            false,
        ));
        let tp = build_tp(&config);
        let entries = tp.write_entries.as_ref().unwrap();

        for entry in entries {
            match entry {
                WriteEntry::Grease(param) => {
                    assert_eq!(
                        param.id.0 % 31,
                        27,
                        "GREASE id {} is not 31*N+27",
                        param.id.0
                    );
                }
                other => panic!("expected Grease, got {other:?}"),
            }
        }
    }

    /// The `version_information` TP (0x11) must be written as a big-endian u32
    /// sequence and ignored on read (unknown TP to the decoder).
    #[test]
    fn version_information_write_and_ignored_on_read() {
        let mut buf = Vec::new();

        // Manually build a WriteEntry::VersionInformation and write it.
        let entry = WriteEntry::VersionInformation {
            chosen_version: 1,
            available: vec![1, 0x0a0a0a0a],
        };
        let params = TransportParameters {
            write_entries: Some(vec![entry]),
            ..TransportParameters::default()
        };
        params.write(&mut buf);

        // Wire format: varint(0x11), varint(12), u32be(1), u32be(1), u32be(0x0a0a0a0a)
        assert_eq!(&buf[..2], &[0x11, 12]); // id=0x11, len=12 (3×4 bytes)
        assert_eq!(&buf[2..6], &[0, 0, 0, 1]); // chosen_version = 1
        assert_eq!(&buf[6..10], &[0, 0, 0, 1]); // available[0] = 1
        assert_eq!(&buf[10..14], &[0x0a, 0x0a, 0x0a, 0x0a]); // available[1] = GREASE

        // The decoder doesn't know 0x11 — it should be silently skipped.
        let decoded = TransportParameters::read(Side::Client, &mut buf.as_slice()).unwrap();
        assert_eq!(decoded, TransportParameters::default());
    }

    /// GREASE version numbers must have each byte's low nibble == 0x0a.
    #[test]
    fn grease_quic_version_format() {
        let mut rng = rand::rng();
        for _ in 0..1000 {
            let v = grease_quic_version(&mut rng);
            let bytes = v.to_be_bytes();
            for byte in bytes {
                assert_eq!(
                    byte & 0x0f,
                    0x0a,
                    "low nibble must be 0x0a, got {byte:#04x}"
                );
            }
        }
    }

    /// `VersionInformation` with a real + GREASE available entry is written with
    /// the correct structure when resolved through TransportParameterKind.
    #[test]
    fn version_information_kind_resolution() {
        use TransportConfig;

        let vi = VersionInformation {
            chosen_version: 1,
            available: vec![VersionEntry::Real(1), VersionEntry::Grease],
        };
        let config = TransportParameterConfig::new(
            vec![TransportParameterKind::VersionInformation(vi)],
            false,
        );
        let mut transport = TransportConfig::default();
        transport.transport_parameter_config(config);

        let mut rng = rand::rng();
        use crate::cid_generator::ConnectionIdGenerator;
        struct FixedLen;
        impl ConnectionIdGenerator for FixedLen {
            fn generate_cid(&mut self) -> ConnectionId {
                ConnectionId::new(&[0u8; 8])
            }
            fn cid_len(&self) -> usize {
                8
            }
            fn cid_lifetime(&self) -> Option<std::time::Duration> {
                None
            }
        }
        let ep_config = EndpointConfig::default();
        let tp = TransportParameters::new(
            &transport,
            &ep_config,
            &FixedLen,
            ConnectionId::new(&[0u8; 8]),
            None,
            &mut rng,
        );

        let entries = tp.write_entries.as_ref().unwrap();
        assert_eq!(entries.len(), 1);
        let WriteEntry::VersionInformation {
            chosen_version,
            available,
        } = &entries[0]
        else {
            panic!("expected VersionInformation entry");
        };
        assert_eq!(*chosen_version, 1);
        assert_eq!(available.len(), 2);
        // One entry must be the real version 1; the other must be a GREASE version.
        // GREASE is inserted at a random position so we don't assert order.
        assert!(available.contains(&1));
        let grease = *available.iter().find(|&&v| v != 1).unwrap();
        for byte in grease.to_be_bytes() {
            assert_eq!(
                byte & 0x0f,
                0x0a,
                "GREASE byte {byte:#04x} low nibble must be 0x0a"
            );
        }
    }
}
