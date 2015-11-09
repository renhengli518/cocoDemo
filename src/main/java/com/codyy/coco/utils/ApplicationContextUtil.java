package com.codyy.coco.utils;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;

/**
 * Spring ApplicationContext工具类. <br>
 * 获取web应用的applicationContext及其管理的bean.
 * <p>
 * Copyright: Copyright (c) 2014年7月23日 上午11:01:19
 * <p>
 * Company: 阔地教育有限公司
 * <p>
 * 
 * @author loujinhe@codyy.com
 * @version 1.0.0
 */
public class ApplicationContextUtil implements ApplicationContextAware {

	private static ApplicationContext applicationContext = null;

	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		if (ApplicationContextUtil.applicationContext == null) {
			ApplicationContextUtil.applicationContext = applicationContext;
		}
	}

	public static ApplicationContext getApplicationContext() {
		return applicationContext;
	}

	/**
	 * 获取applicationContext中的bean
	 * 
	 * @param name
	 *            beanId
	 * @param requiredType
	 *            bean类型
	 * @return bean
	 */
	public static <T> T getBean(String name, Class<T> requiredType) {
		return getApplicationContext().getBean(name, requiredType);
	}
}
