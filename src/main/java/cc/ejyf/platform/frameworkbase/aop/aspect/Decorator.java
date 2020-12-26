package cc.ejyf.platform.frameworkbase.aop.aspect;

import cc.ejyf.platform.frameworkbase.env.RedisVar;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Objects;

@Component
@Aspect
@Order(2)
public class Decorator {
    Logger logger = LoggerFactory.getLogger(Decorator.class);
    @Autowired
    private RedisVar redisVar;
    private DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    @Pointcut("@annotation(cc.ejyf.platform.frameworkbase.aop.annotation.Decorate)")
    public void decorationAsp() {
    }


    @Around("decorationAsp()")
    public Object around000(ProceedingJoinPoint pjp) throws Throwable {
        LinkedHashMap<String, Object> map = new LinkedHashMap<>(4);
        //可以对传入参数也进行包装或者解包。这里没有写。
        Object o;
        try {
            o = pjp.proceed();
            map.put("code", "000000");
            map.put("msg", "success");
            map.put("data", o);
        } catch (Exception e) {
            e.printStackTrace();
            //一个简单的处理方式，可以根据需要，映射成具体的响应代码和错误原因。
            String exceptionName = e.getClass().getSimpleName();//just example
            String i18nName = exceptionName.trim();//just example
            String errCode = exceptionName.trim();//just example
            map.put("code", errCode);
            map.put("msg", i18nName);
            map.put("data", Objects.requireNonNullElse(e.getMessage(), "internal error."));
        }
//        map.put("timestamp", redisVar.redis.boundValueOps(redisVar.clockKey).get());
        map.put("timestamp", LocalDateTime.now()
                .atZone(ZoneId.systemDefault())
                .format(formatter));
        return map;
    }
}
