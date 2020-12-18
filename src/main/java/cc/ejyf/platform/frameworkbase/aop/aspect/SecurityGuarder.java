package cc.ejyf.platform.frameworkbase.aop.aspect;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@Aspect
@Order(3)
public class SecurityGuarder {
    @Pointcut("@annotation(cc.ejyf.platform.frameworkbase.aop.annotation.Authorize)")
    public void securityGuardAsp() {
    }
    @Around("securityGuardAsp()")
    public Object around000(ProceedingJoinPoint pjp) throws Throwable {
        System.out.println("guard");
        return pjp.proceed();
    }
}
