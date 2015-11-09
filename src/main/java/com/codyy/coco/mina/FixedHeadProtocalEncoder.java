package com.codyy.coco.mina;

import java.nio.charset.Charset;

import org.apache.mina.core.buffer.IoBuffer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolEncoderAdapter;
import org.apache.mina.filter.codec.ProtocolEncoderOutput;

public class FixedHeadProtocalEncoder extends ProtocolEncoderAdapter {

	@SuppressWarnings("unused")
	private final Charset charset;

	public FixedHeadProtocalEncoder(Charset charset) {
		this.charset = charset;
	}

	public void encode(IoSession session, Object message,
			ProtocolEncoderOutput out) throws Exception {
		if (message != null) {
			String value = (String) message;
			IoBuffer buf = IoBuffer.allocate(value.getBytes().length);
			buf.setAutoExpand(true);
			buf.put(value.getBytes());
			buf.flip();
			out.write(buf);
		}
	}

}