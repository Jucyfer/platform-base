package cc.ejyf.platform.frameworkbase.aop.aspect;

import cc.ejyf.platform.frameworkbase.aop.annotation.Cryptable;
import cc.ejyf.platform.frameworkbase.aop.util.MixinCryptor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.NoSuchElementException;

/**
 * <div>这个AOP类被命名为8A是有原因的：</div>
 * <div>其必须保证是优先于所有其他AOP类之前得到执行<pre>（即，处于所有增强类的最外圈）</pre>负责加密或解密目标方法上的参数及返回值。</div>
 * <br/>即使本class中加上了{@linkplain Order @Order(1)}的注解，也必须保证其在Order值重复的情况下拥有优先执行权。
 */
@Component
@Aspect
@Order(1)
public class AAAAAAAA {
    private Logger logger = LoggerFactory.getLogger(AAAAAAAA.class);
    private ObjectMapper mapper = new ObjectMapper();
    @Value("{$server.encrypt.store.redis.key}")
    private String redisEncHash;
    @Value("{$server.encrypt.store.redis.key.pri.index}")
    private String redisPriIndex;
    @Value("{$server.encrypt.store.redis.token.pub.hash}")
    private String redisTokenPubHash;
    @Autowired
    private StringRedisTemplate redis;
    @Autowired
    private MixinCryptor mixinCryptor;


    @Pointcut("@annotation(cc.ejyf.platform.frameworkbase.aop.annotation.Cryptable)")
    public void cryptionAsp() {
    }


    @Around("cryptionAsp()")
    public Object around000(ProceedingJoinPoint pjp) throws Throwable {
        MethodSignature methodSignature = (MethodSignature) pjp.getSignature();
        Object originReturn;
        //mustn't null,cuz aspect is on it.
        Cryptable cryptable = methodSignature.getMethod().getAnnotation(Cryptable.class);
        if (cryptable.aesDec()) {
            HashMap<String, Object> requestBodyEnc = getMethodArgByClass(pjp, HashMap.class);
            String keyData = (String) requestBodyEnc.get(cryptable.keyIndex());
            String valData = (String) requestBodyEnc.get(cryptable.dataIndex());
            String serverPriKeyStr = redis.<String, String>boundHashOps(redisEncHash).get(redisPriIndex);
            String key_dec = mixinCryptor.rsaStr2StrPriDecrypt(keyData, serverPriKeyStr);
            String data_dec = mixinCryptor.aesStr2StrDecrypt(valData, key_dec);
            LinkedHashMap<String, Object> realBody = mapper.readValue(data_dec, LinkedHashMap.class);
            Object[] args = pjp.getArgs();
            for (int i = 0, len = args.length; i < len; i++) {
                if (args[i] instanceof HashMap) {
                    args[i] = realBody;
                }
            }
            originReturn = pjp.proceed(args);
        } else {
            originReturn = pjp.proceed();
        }
        //若AES加密被打开（默认打开），则对返回报文进行加密
        if (cryptable.aesEnc()) {
            String castedReturn;
            if(originReturn instanceof String){
                castedReturn = (String) originReturn;
            }else{
                castedReturn = mapper.writeValueAsString(originReturn);
            }
            HashMap<String, String> facade = new HashMap<>(2);
            String randAES = mixinCryptor.generateAES(256);
            String encryptedData = mixinCryptor.aesStr2StrEncrypt(castedReturn, randAES);
            facade.put(cryptable.dataIndex(), encryptedData);
            if (!cryptable.rsaPubEnc()) {
                //表示该接口客户端未鉴真，keyindex使用明文随机AES
                facade.put(cryptable.keyIndex(), randAES);
            } else {
                //表示该接口客户端已鉴真，使用客户端公钥和随机AES
                /*
                 * head里传来的是token，token和用户id关联，问题在于公钥和token还是和id关联。
                 * 还是跟token关联，其后可能会扩展出多端同时登录的需求。一个token对应一个pub+pri。
                 */
                String token = getMethodArgByClassAndName(pjp, String.class, "token");
                String clientPub = redis.<String, String>boundHashOps(redisTokenPubHash).get(token);
                facade.put(cryptable.keyIndex(), mixinCryptor.rsaStr2StrPubEncrypt(randAES, clientPub));
            }
            return mapper.writeValueAsString(facade);
        }
        //若AES加密被关闭，则直接返回明文报文
        return originReturn;

    }

    private <T> T getMethodArgByClass(JoinPoint joinPoint, Class<T> clz) throws NoSuchElementException {
        Object[] args = joinPoint.getArgs();
        for (int i = 0; i < args.length; i++) {
            if (clz.isInstance(args[i])) {
                return clz.cast(args[i]);
            }
        }
        throw new NoSuchElementException(clz.getName());
    }

    private Object getMethodArgByName(JoinPoint joinPoint, String paramName) throws NoSuchElementException {
        Object[] args = joinPoint.getArgs();
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] names = signature.getParameterNames();
        for (int i = 0; i < args.length; i++) {
            if (names[i].equals(paramName)) {
                return args[i];
            }
        }
        throw new NoSuchElementException(paramName);
    }

    private <T> T getMethodArgByClassAndName(JoinPoint joinPoint, Class<T> clz, String paramName) throws NoSuchElementException {
        Object[] args = joinPoint.getArgs();
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        String[] names = signature.getParameterNames();
        for (int i = 0; i < args.length; i++) {
            if (names[i].equals(paramName) && names[i] != null) {
                if (clz.isInstance(args[i])) {
                    return clz.cast(args[i]);
                } else {
                    logger.error("捕获参数中的名称，但是类型不匹配或者为null");
                    throw new NoSuchElementException(clz.getName() + " & " + paramName);
                }
            }
        }
        throw new NoSuchElementException(clz.getName() + " & " + paramName);
    }


}
