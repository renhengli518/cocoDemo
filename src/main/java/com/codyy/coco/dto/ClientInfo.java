package com.codyy.coco.dto;

import org.apache.mina.core.session.IoSession;

public class ClientInfo {

	/** 对应每个客户端的连接 */
	private IoSession session;

	/** 客户端from */
	private String userId;

	/** 组 */
	private String groupId;

	public ClientInfo(String userId, String groupId) {
		this.userId = userId;
		this.groupId = groupId;
	}

	public ClientInfo(IoSession session, String userId, String groupId) {
		this.session = session;
		this.userId = userId;
		this.groupId = groupId;
	}

	public IoSession getSession() {
		return session;
	}

	public void setSession(IoSession session) {
		this.session = session;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getGroupId() {
		return groupId;
	}

	public void setGroupId(String groupId) {
		this.groupId = groupId;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((groupId == null) ? 0 : groupId.hashCode());
		result = prime * result + ((userId == null) ? 0 : userId.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ClientInfo other = (ClientInfo) obj;
		if (groupId == null) {
			if (other.groupId != null)
				return false;
		} else if (!groupId.equals(other.groupId))
			return false;
		if (userId == null) {
			if (other.userId != null)
				return false;
		} else if (!userId.equals(other.userId))
			return false;
		return true;
	}

}
