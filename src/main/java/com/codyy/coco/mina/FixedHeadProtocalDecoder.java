package com.codyy.coco.mina;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.AttributeKey;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolDecoderException;
import org.apache.mina.filter.codec.ProtocolDecoderOutput;
import org.apache.mina.filter.codec.RecoverableProtocolDecoderException;

public class FixedHeadProtocalDecoder implements ProtocolDecoder {

	private final Charset charset = Charset.forName("UTF-8");
	private int maxLineLength = Integer.MAX_VALUE;
	private int bufferLength = 128;

	private final AttributeKey CONTEXT = new AttributeKey(
			FixedHeadProtocalDecoder.class, "context");

	@SuppressWarnings("unused")
	private final CharsetDecoder decoder;

	public FixedHeadProtocalDecoder() {
		this(Charset.defaultCharset());
	}

	public FixedHeadProtocalDecoder(Charset charset) {
		this.decoder = charset.newDecoder();
	}

	public void decode(IoSession session, IoBuffer in, ProtocolDecoderOutput out)
			throws Exception {
		/*
		 * IoBuffer bufTmp = null; byte[] buf = (byte[])
		 * session.getAttribute(CONTEXT); if (buf == null) { bufTmp = in; } else
		 * { bufTmp = IoBuffer.allocate(buf.length + in.remaining());
		 * bufTmp.setAutoExpand(true); bufTmp.put(buf); bufTmp.put(in);
		 * bufTmp.flip(); } List<Byte> message = new LinkedList<Byte>(); while
		 * (bufTmp.remaining() > 0) { byte b = bufTmp.get(); message.add(b); if
		 * (b == Constant.SPLIT_ZERO || b == Constant.SPLIT_NEWLINE) { byte[]
		 * bArray = new byte[message.size()]; for (int i = 0; i <
		 * message.size(); i++) { bArray[i] = message.get(i); } String content =
		 * new String(bArray, Constant.DEFAULT_CHARSET); out.write(content);
		 * session.removeAttribute(CONTEXT); break; } } if
		 * (bufTmp.hasRemaining()) { byte[] tmpb = new byte[bufTmp.remaining()];
		 * bufTmp.get(tmpb); session.setAttribute(CONTEXT, tmpb); }
		 */
		Context ctx = getContext(session);
		decodeAuto(ctx, session, in, out);
	}

	private Context getContext(IoSession session) {
		Context ctx;
		ctx = (Context) session.getAttribute(CONTEXT);

		if (ctx == null) {
			ctx = new Context(bufferLength);
			session.setAttribute(CONTEXT, ctx);
		}

		return ctx;
	}

	private void decodeAuto(Context ctx, IoSession session, IoBuffer in,
			ProtocolDecoderOutput out) throws CharacterCodingException,
			ProtocolDecoderException {
		int matchCount = ctx.getMatchCount();

		// Try to find a match
		int oldPos = in.position();
		int oldLimit = in.limit();

		while (in.hasRemaining()) {
			byte b = in.get();
			boolean matched = false;

			switch (b) {
				case '\r' :
					matchCount++;
					matched = true;
					break;

				case '\0' :
					matchCount++;
					matched = true;
					break;

				default :
					matchCount = 0;
			}

			if (matched) {
				// Found a match.
				int pos = in.position();
				in.limit(pos);
				in.position(oldPos);

				ctx.append(in);

				in.limit(oldLimit);
				in.position(pos);

				if (ctx.getOverflowPosition() == 0) {
					IoBuffer buf = ctx.getBuffer();
					buf.flip();
					buf.limit(buf.limit() - matchCount);

					try {
						byte[] data = new byte[buf.limit()];
						buf.get(data);
						CharsetDecoder decoder = ctx.getDecoder();

						CharBuffer buffer = decoder.decode(ByteBuffer
								.wrap(data));
						String str = new String(buffer.array());
						out.write(str);
					} finally {
						buf.clear();
					}
				} else {
					int overflowPosition = ctx.getOverflowPosition();
					ctx.reset();
					throw new RecoverableProtocolDecoderException(
							"Line is too long: " + overflowPosition);
				}

				oldPos = pos;
				matchCount = 0;
			}
		}

		// Put remainder to buf.
		in.position(oldPos);
		ctx.append(in);

		ctx.setMatchCount(matchCount);
	}

	private class Context {
		/** The decoder */
		private final CharsetDecoder decoder;

		/** The temporary buffer containing the decoded line */
		private final IoBuffer buf;

		/** The number of lines found so far */
		private int matchCount = 0;

		/** A counter to signal that the line is too long */
		private int overflowPosition = 0;

		/** Create a new Context object with a default buffer */
		private Context(int bufferLength) {
			decoder = charset.newDecoder();
			buf = IoBuffer.allocate(bufferLength).setAutoExpand(true);
		}

		public CharsetDecoder getDecoder() {
			return decoder;
		}

		public IoBuffer getBuffer() {
			return buf;
		}

		public int getOverflowPosition() {
			return overflowPosition;
		}

		public int getMatchCount() {
			return matchCount;
		}

		public void setMatchCount(int matchCount) {
			this.matchCount = matchCount;
		}

		public void reset() {
			overflowPosition = 0;
			matchCount = 0;
			decoder.reset();
		}

		public void append(IoBuffer in) {
			if (overflowPosition != 0) {
				discard(in);
			} else if (buf.position() > maxLineLength - in.remaining()) {
				overflowPosition = buf.position();
				buf.clear();
				discard(in);
			} else {
				getBuffer().put(in);
			}
		}

		private void discard(IoBuffer in) {
			if (Integer.MAX_VALUE - in.remaining() < overflowPosition) {
				overflowPosition = Integer.MAX_VALUE;
			} else {
				overflowPosition += in.remaining();
			}

			in.position(in.limit());
		}
	}

	public void finishDecode(IoSession session, ProtocolDecoderOutput out)
			throws Exception {
	}

	public void dispose(IoSession session) throws Exception {
		session.removeAttribute(CONTEXT);
	}
}