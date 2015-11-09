package com.codyy.coco.dto;

public class Message {

	private String type;
	private String from;
	private String to;
	private String gid;
	private String enterpriseId;//企业编号
	private String serverType;//服务器类型(0：会议界面  1：主界面)
	private String license;
	private String cipher;//加密流程密文。如果消息包含cipher属性，则Coco服务器验证密文是否正确；如果不包含，则不验证。
	private String remainSeconds;//剩余使用时间，以秒表示
	private String say;//主界面返回所有在线人员；会议界面返回群组在线人员。当人员超过200人时，分组发送;人员的ID号
	private String result;//0:License认证失败;1:License认证成功;2:License服务到期;3:会议界面超过点数;
	private String life;//软件使用天数
	
	private String sendNick;
	private String group; 
	
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getFrom() {
		return from;
	}
	public void setFrom(String from) {
		this.from = from;
	}
	public String getTo() {
		return to;
	}
	public void setTo(String to) {
		this.to = to;
	}
	public String getGid() {
		return gid;
	}
	public void setGid(String gid) {
		this.gid = gid;
	}
	public String getEnterpriseId() {
		return enterpriseId;
	}
	public void setEnterpriseId(String enterpriseId) {
		this.enterpriseId = enterpriseId;
	}
	public String getServerType() {
		return serverType;
	}
	public void setServerType(String serverType) {
		this.serverType = serverType;
	}
	public String getLicense() {
		return license;
	}
	public void setLicense(String license) {
		this.license = license;
	}
	public String getCipher() {
		return cipher;
	}
	public void setCipher(String cipher) {
		this.cipher = cipher;
	}
	public String getRemainSeconds() {
		return remainSeconds;
	}
	public void setRemainSeconds(String remainSeconds) {
		this.remainSeconds = remainSeconds;
	}
	public String getSay() {
		return say;
	}
	public void setSay(String say) {
		this.say = say;
	}
	public String getResult() {
		return result;
	}
	public void setResult(String result) {
		this.result = result;
	}
	public String getLife() {
		return life;
	}
	public void setLife(String life) {
		this.life = life;
	}
	public String getSendNick() {
		return sendNick;
	}
	public void setSendNick(String sendNick) {
		this.sendNick = sendNick;
	}
	
	public String getGroup() {
		return group;
	}
	
	public void setGroup(String group) {
		this.group = group;
	}
}
