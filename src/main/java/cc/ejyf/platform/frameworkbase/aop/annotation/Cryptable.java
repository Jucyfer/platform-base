package cc.ejyf.platform.frameworkbase.aop.annotation;

import java.lang.annotation.*;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Cryptable {
    boolean aesEnc() default true;
    boolean aesDec() default true;
    boolean rsaPubEnc() default true;
    boolean rsaPubDec() default false;
    boolean rsaPriEnc() default false;
    boolean rsaPriDec() default true;
    String keyIndex() default "b";
    String dataIndex() default "l";
}
