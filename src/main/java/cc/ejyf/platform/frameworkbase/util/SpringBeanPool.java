package cc.ejyf.platform.frameworkbase.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

@Component
public class SpringBeanPool implements ApplicationContextAware {
    private Logger logger = LoggerFactory.getLogger(SpringBeanPool.class);
    private static ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        if (SpringBeanPool.applicationContext == null) {
            SpringBeanPool.applicationContext = applicationContext;
        }
    }

    public static ApplicationContext getApplicationContext() {
        return applicationContext;
    }

    public static Object findBean(String name) {
        try {
            return getApplicationContext().getBean(name);
        } catch (Exception e) {
            return null;
        }
    }

    public static <T> T findBean(Class<T> clazz) {
        try {
            return getApplicationContext().getBean(clazz);
        } catch (Exception e) {
            return null;
        }
    }

    public static <T> T findBean(String name, Class<T> clazz) {
        try {
            return getApplicationContext().getBean(name, clazz);
        } catch (Exception e) {
            return null;
        }
    }
}
