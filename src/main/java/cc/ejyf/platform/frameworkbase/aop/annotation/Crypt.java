package cc.ejyf.platform.frameworkbase.aop.annotation;

import cc.ejyf.platform.frameworkbase.aop.DecryptMode;
import cc.ejyf.platform.frameworkbase.aop.EncryptMode;

import java.lang.annotation.*;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Crypt {

    boolean hasBody() default true;
    EncryptMode encryptMode() default EncryptMode.RSA_AES_R_FUSE;
    DecryptMode decryptMode() default DecryptMode.RSA_AES_R_FUSE;

    String keyIndex() default "b";
    String dataIndex() default "l";
}
