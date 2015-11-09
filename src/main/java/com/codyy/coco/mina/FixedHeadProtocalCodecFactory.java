package com.codyy.coco.mina;

import java.nio.charset.Charset;

import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.codec.ProtocolCodecFactory;
import org.apache.mina.filter.codec.ProtocolDecoder;
import org.apache.mina.filter.codec.ProtocolEncoder;

import com.codyy.coco.constant.Constant;

public class FixedHeadProtocalCodecFactory implements ProtocolCodecFactory {

	private final FixedHeadProtocalEncoder encoder;

	private final FixedHeadProtocalDecoder decoder;

	public FixedHeadProtocalCodecFactory() {
		this(Charset.forName(Constant.DEFAULT_CHARSET));
	}

	public FixedHeadProtocalCodecFactory(Charset charset) {
		encoder = new FixedHeadProtocalEncoder(charset);
		decoder = new FixedHeadProtocalDecoder(charset);
	}

	public ProtocolEncoder getEncoder(IoSession session) {
		return encoder;
	}

	public ProtocolDecoder getDecoder(IoSession session) {
		return decoder;
	}

}
