package cc.ejyf.platform.frameworkbase.aop.aspect;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.util.*;

@Component
@Aspect
@Order(2)
public class Decorator {
    Logger logger = LoggerFactory.getLogger(Decorator.class);

    @Pointcut("@annotation(cc.ejyf.platform.frameworkbase.aop.annotation.Decorate)")
    public void decorationAsp() {
    }


    @Around("decorationAsp()")
    public Object around000(ProceedingJoinPoint pjp) throws Throwable {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>(3);
        MethodSignature methodSignature = (MethodSignature) pjp.getSignature();
        RequestMapping requestMapping =methodSignature.getMethod().getDeclaredAnnotation(RequestMapping.class);
        Object o;
        try {
            o = pjp.proceed();
            map.put("code", "000000");
            map.put("msg", "success");
            map.put("data", o);
        } catch (Exception e) {
            String exceptionName = e.getClass().getSimpleName();
            String i18nName = exceptionName.trim();
            String errCode = exceptionName.trim();
            map.put("code", errCode);
            map.put("msg", i18nName);
            map.put("data", Objects.requireNonNullElse(e.getMessage(), "internal error."));
        }
        return map;
    }
}
