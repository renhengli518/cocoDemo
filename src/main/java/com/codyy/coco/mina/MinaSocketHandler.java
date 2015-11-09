package com.codyy.coco.mina;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IoSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.CollectionUtils;

import com.codyy.coco.constant.Constant;
import com.codyy.coco.dto.ClientInfo;
import com.codyy.coco.dto.Message;
import com.codyy.coco.utils.XMLAndStringUtil;

public class MinaSocketHandler extends IoHandlerAdapter {
	
	private static final Logger logger = LoggerFactory.getLogger(MinaSocketHandler.class);

	/** key:groupId,value:ClientInfo set */
	private Map<String, Set<ClientInfo>> groupClientMap = new HashMap<String, Set<ClientInfo>>();

	/** key:userId,value:ClientInfo */
	private Map<String, ClientInfo> userGroupMap = new HashMap<String, ClientInfo>();
	
	/** key:sessionId,value:ClientInfo */
	private Map<Long, ClientInfo> sessionUserMap = new HashMap<Long, ClientInfo>();

	/** 锁，控制groupClientMap和userGroupMap的并发访问 */
	private final ReadWriteLock lock = new ReentrantReadWriteLock();

	@Override
	public void exceptionCaught(IoSession session, Throwable cause)
			throws Exception {
		super.exceptionCaught(session, cause);
	}

	@Override
	public void messageReceived(IoSession session, Object message)
			throws Exception {
		super.messageReceived(session, message);
		messageHandle(session, (String) message);
	}

	@Override
	public void sessionClosed(IoSession session) throws Exception {
		super.sessionClosed(session);
		loginout(session); //连接关闭后自动下线
	}

	/**
	 * 接收到的信息处理
	 * 
	 * @param xmlString
	 * @throws IOException
	 */
	public void messageHandle(IoSession session, String xmlString)
			throws IOException {
		Message doc = XMLAndStringUtil.stringXMLToJavaBean(xmlString);
		if ("login".equalsIgnoreCase(doc.getType())) {
			login(session, doc);
		} else if ("noticeOnline".equalsIgnoreCase(doc.getType())) {
			noticeOnline(session, doc);
		} else if ("loginout".equalsIgnoreCase(doc.getType())) {
			if(session != null) {
				session.close(true);
			}
		} else if ("keepAlive".equalsIgnoreCase(doc.getType())) {// 原样返回
			keepAlive(session, xmlString);
		} else if ("text".equalsIgnoreCase(doc.getType())) {// 单人发送
			text(session, doc, xmlString);
		} else if ("meet".equalsIgnoreCase(doc.getType())
				|| "group".equalsIgnoreCase(doc.getType())) {// 组内发送
			meetOrGroup(session, doc, xmlString);
		} else if ("getGroupUser".equalsIgnoreCase(doc.getType())) { // 获取在线群组
			getGroupUser(session, doc);
		} else {
			session.write(convert(Constant.LINK_MESSAGE,
					Constant.SPLIT_ZERO));
		}
	}

	/**
	 * 登录
	 * 
	 * @param doc
	 *            登录信息
	 * @throws IOException
	 */
	private void login(IoSession session, Message doc) throws IOException {
		ClientInfo clientInfo = new ClientInfo(session, doc.getFrom(),
				doc.getGid());

		StringBuilder say = new StringBuilder();
		try {
			lock.writeLock().lock();

			userGroupMap.put(doc.getFrom(), clientInfo);
			sessionUserMap.put(session.getId(), clientInfo);

			// 维护groupClientMap
			Set<ClientInfo> clientInfoSet = groupClientMap.get(doc
					.getGid());
			if (clientInfoSet == null) {
				clientInfoSet = new HashSet<ClientInfo>();
				groupClientMap.put(doc.getGid(), clientInfoSet);
			}
			clientInfoSet.remove(clientInfo);
			clientInfoSet.add(clientInfo);

			for (ClientInfo client : clientInfoSet) {
				say.append(client.getUserId()).append(",");
			}
			if (say.toString().endsWith(",")) {
				say.deleteCharAt(say.length() - 1);
			}
		} finally {
			lock.writeLock().unlock();
		}

		session.write(convert(buildLoginResult(doc, say),
				Constant.SPLIT_NEWLINE));
	}

	/**
	 * 上线
	 * 
	 * @param doc
	 * @throws IOException
	 */
	private void noticeOnline(IoSession session, Message doc)
			throws IOException {
		Set<ClientInfo> tempClientSet = null;

		try {
			lock.readLock().lock();
			if (sessionUserMap.containsKey(session.getId())) {
				Set<ClientInfo> clientInfoSet = groupClientMap.get(doc
						.getGid());
				if (!CollectionUtils.isEmpty(clientInfoSet)) {
					tempClientSet = new HashSet<ClientInfo>(
							clientInfoSet);
				}
			}
		} finally {
			lock.readLock().unlock();
		}

		if (!CollectionUtils.isEmpty(tempClientSet)) {
			for (ClientInfo clientInfo : tempClientSet) {
				clientInfo.getSession().write(convert(
						buildNoticeOnlineResult(doc,
								clientInfo.getUserId()),
								Constant.SPLIT_NEWLINE));
			}
		}
	}

	/**
	 * 下线
	 * 
	 * @param doc
	 * @throws IOException
	 */
	private void loginout(IoSession session)
			throws IOException {
		Set<ClientInfo> tempClientSet = null;
		String from  = "";
		try {
			lock.writeLock().lock();
			
			ClientInfo handler = sessionUserMap.remove(session.getId());
			if (handler != null) {
				from  = handler.getUserId();
				userGroupMap.remove(from);
				Set<ClientInfo> clientInfoSet = groupClientMap
						.get(handler.getGroupId());
				if (clientInfoSet != null) {// 有这个组
					clientInfoSet.remove(new ClientInfo(from, handler.getGroupId()));

					if (!CollectionUtils.isEmpty(clientInfoSet)) {
						tempClientSet = new HashSet<ClientInfo>(
								clientInfoSet);
					}
				}
			}
		} finally {
			lock.writeLock().unlock();
		}

		if (!CollectionUtils.isEmpty(tempClientSet)) {
			for (ClientInfo clientInfo : tempClientSet) {
				StringBuilder loginOut = new StringBuilder();
				loginOut.append("<root from='").append(from).append("' to='")
						.append(clientInfo.getUserId())
						.append("' type='loginout' />");
				 clientInfo.getSession().write(convert(loginOut.toString(),
				 Constant.SPLIT_NEWLINE));
			}
		}
	}

	/**
	 * 心跳
	 * 
	 * @param xmlString
	 * @throws IOException
	 */
	private void keepAlive(IoSession session, String xmlString)
			throws IOException {
		session.write(xmlString+"\r");
	}

	/**
	 * 单独发送
	 * 
	 * @param doc
	 * @throws IOException
	 */
	private void text(IoSession fromSession, Message doc, String xmlString)
			throws IOException {
		boolean flag = false;
		IoSession toSession = null;
		try {
			lock.readLock().lock();
			flag = sessionUserMap.containsKey(fromSession.getId())
					&& userGroupMap.containsKey(doc.getTo());
					toSession = userGroupMap.get(doc.getTo()).getSession();
		} finally {
			lock.readLock().unlock();
		}
		if (flag) {
			toSession.write(xmlString+"\r");
		}
	}

	/**
	 * 群发
	 * 
	 * @param doc
	 * @throws IOException
	 */
	private void meetOrGroup(IoSession session, Message doc, String xmlString)
			throws IOException {
		Set<ClientInfo> tempClientSet = null;
		try {
			lock.readLock().lock();
			if (sessionUserMap.containsKey(session.getId())
					&& groupClientMap.containsKey(doc.getTo())) {
				Set<ClientInfo> clientInfoSet = groupClientMap.get(doc
						.getTo());
				if (!CollectionUtils.isEmpty(clientInfoSet)) {
					tempClientSet = new HashSet<ClientInfo>(
							clientInfoSet);
				}
			}
		} finally {
			lock.readLock().unlock();
		}

		if (!CollectionUtils.isEmpty(tempClientSet)) {
			for (ClientInfo clientInfo : tempClientSet) {
				clientInfo.getSession().write(xmlString + "\r");
			}
		}
	}
	
	private void getGroupUser(IoSession session, Message doc) {
		StringBuilder say = new StringBuilder();
		try {
			lock.readLock().lock();
			if (sessionUserMap.containsKey(session.getId())) {
				Set<ClientInfo> clientInfoSet = groupClientMap.get(doc
						.getGroup());
				if (clientInfoSet != null) {
					for (ClientInfo clientInfo : clientInfoSet) {
						say.append(clientInfo.getUserId()).append(",");
					}
					if (say.toString().endsWith(",")) {
						say.deleteCharAt(say.length() - 1);
					}
				}
			}
		} finally {
			lock.readLock().unlock();
		}
		session.write(convert(buildGetGroupUser(doc, say),
				Constant.SPLIT_NEWLINE));
	}

	/**
	 * 构造login返回文本
	 * 
	 * @param doc
	 * @param say
	 * @return
	 */
	private String buildLoginResult(Message doc, StringBuilder say) {
		StringBuilder loginResult = new StringBuilder();
		loginResult.append("<root type='loadUser' from='")
				.append(doc.getFrom()).append("' to='").append(doc.getFrom())
				.append("' api='").append(doc.getType()).append("' gid='")
				.append(doc.getGid()).append("' enterpriseId='")
				.append(doc.getEnterpriseId()).append("' serverType='")
				.append(doc.getServerType()).append("' license='' cipher='")
				.append(doc.getCipher())
				.append("' remainSeconds='-9999' say='").append(say)
				.append("' result='1' life='-9999' />");
		return loginResult.toString();
	}

	/**
	 * 构建noticeOnline返回文本
	 * 
	 * @param doc
	 * @param toUserId
	 * @return
	 */
	private String buildNoticeOnlineResult(Message doc, String toUserId) {
		StringBuilder notice = new StringBuilder();
		notice.append("<root api='").append(doc.getType())
				.append("' type='login' from='").append(doc.getFrom())
				.append("' send_nick='").append(doc.getSendNick())
				.append("' gid='").append(doc.getGid())
				.append("' enterpriseId='").append(doc.getEnterpriseId())
				.append("' serverType='0' license='' cipher='")
				.append(doc.getCipher()).append("' to='").append(toUserId)
				.append("' />");
		return notice.toString();
	}

	/**
	 * 构造getGroupUser返回结果
	 * 
	 * @param doc
	 * @param say
	 * @return
	 */
	private String buildGetGroupUser(Message doc, StringBuilder say) {
		StringBuilder loginResult = new StringBuilder();
		loginResult.append("<root type='loadGroupUser' send_nick='")
				.append(doc.getSendNick()).append("' time='")
				.append(new Date().getTime()).append("' from='")
				.append(doc.getFrom()).append("' to='").append(doc.getTo())
				.append("' api='").append("getGroupOnlineUser")
				.append("' group='").append(doc.getGroup())
				.append("' enterpriseId='").append(doc.getEnterpriseId())
				.append("' serverType='").append(doc.getServerType())
				.append("' cipher='").append(doc.getCipher()).append("' say='")
				.append(say).append("' />");
		return loginResult.toString();
	}
	
	/*private String modifyEndChar(String srcStr) {
		byte[] bArray;
		try {
			bArray = srcStr.getBytes(Constant.DEFAULT_CHARSET);
		} catch (UnsupportedEncodingException e) {
			logger.error("字符转换异常", e);
			return "";
		}
		bArray[bArray.length-1] = (byte)Constant.SPLIT_NEWLINE;
		try {
			return new String(bArray, Constant.DEFAULT_CHARSET);
		} catch (UnsupportedEncodingException e) {
			logger.error("字符转换异常", e);
			return "";
		}
	}*/

	private String convert(String srcStr, char split) {
		byte[] b = null;
		try {
			b = srcStr.getBytes(Constant.DEFAULT_CHARSET);
		} catch (UnsupportedEncodingException e) {
			logger.error("字节编码转换异常", e);
		}
		int srcDataLength = b.length;
		byte[] targetData = new byte[srcDataLength + 1];
		System.arraycopy(b, 0, targetData, 0, srcDataLength);
		targetData[srcDataLength] = (byte) split;
		try {
			return new String(targetData, Constant.DEFAULT_CHARSET);
		} catch (UnsupportedEncodingException e) {
			logger.error("字节编码转换异常", e);
		}
		return "";
	}

}
