package cc.ejyf.platform.frameworkbase.aop.aspect;

import cc.ejyf.platform.frameworkbase.aop.DecryptMode;
import cc.ejyf.platform.frameworkbase.aop.EncryptMode;
import cc.ejyf.platform.frameworkbase.aop.annotation.Crypt;
import cc.ejyf.platform.frameworkbase.env.RedisVar;
import cc.ejyf.platform.frameworkbase.util.MixinCryptor;
import cc.ejyf.platform.frameworkbase.util.tuples.Tuple4;
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
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

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
    @Autowired
    private MixinCryptor mixinCryptor;
    @Autowired
    private RedisVar redisVar;


    @Pointcut("@annotation(cc.ejyf.platform.frameworkbase.aop.annotation.Crypt)")
    public void cryptionAsp() {
    }


    @Around("cryptionAsp()")
    public Object around000(ProceedingJoinPoint pjp) throws Throwable {
        MethodSignature methodSignature = (MethodSignature) pjp.getSignature();
        Object[] args = pjp.getArgs();
        Class[] classes = methodSignature.getParameterTypes();
        String[] names = methodSignature.getParameterNames();
        /*
         * 新的映射方式，直接通过Map取参数，遍历一次，映射N次。
         * 有名称的前提下，任何一个参数都随意提取、修改。
         * 也可以再次并发遍历。
         */
        HashMap<String, Tuple4<String, Class<?>, Object, Integer>> paramMap = IntStream.iterate(0, i -> i + 1)
                .limit(args.length)
                //默认认为参数表不会很长，就单线程了
//                .parallel()
                .mapToObj(i -> new Tuple4<String, Class<?>, Object, Integer>(names[i], classes[i], args[i], i))
                .collect(
                        Collectors.toMap(
                                t -> t.e1,
                                t -> t,
                                (t1, t2) -> t1,
                                HashMap::new
                        )
                );

        Object originReturn;
        //mustn't null,cuz aspect is on it.
        //xxxDec must be true, or else won't tag this annotation.
        Crypt crypt = methodSignature.getMethod().getAnnotation(Crypt.class);
        //解密部分，先判断是否具有body，再走模式分叉
        if (!crypt.hasBody() || crypt.decryptMode() == DecryptMode.NONE) {
            originReturn = pjp.proceed();
        } else {
            Tuple4<String, Class<?>, Object, Integer> bodyTuple = paramMap.get("body");
            HashMap<String, Object> requestBodyEnc = (HashMap) bodyTuple.e3;
            String keyData = (String) requestBodyEnc.get(crypt.keyIndex());
            String valData = (String) requestBodyEnc.get(crypt.dataIndex());
            String aes = "";
            switch (crypt.decryptMode()) {
                case RSA_AES_R_FUSE:
                    String serverPriKeyStr = redisVar.redis.<String, String>boundHashOps(redisVar.redisEncHash).get(redisVar.redisPriIndex);
                    aes = mixinCryptor.rsaStr2StrPriDecrypt(keyData, serverPriKeyStr);
                    break;
                case RSA_AES_C_FUSE:
                case AES_C_FUSE:
                    String token = (String) paramMap.get("token").e3;//这里概率会有一个待定的NullPointerException。用开发文档强制规定使用这两个选项必须指定token
                    aes = redisVar.redis.<String, String>boundHashOps(redisVar.redisTokenSecHash).get(token);
                    break;
                case AES_R_PLAIN:
                    aes = keyData;
                default:
                    break;
            }
            String data_dec = mixinCryptor.aesStr2StrDecrypt(valData, aes);
            LinkedHashMap<String, Object> realBody = mapper.readValue(data_dec, LinkedHashMap.class);
            args[bodyTuple.e4] = realBody;
            originReturn = pjp.proceed(args);
        }
        if (crypt.encryptMode() == EncryptMode.NONE) {
            return originReturn;
        }
        String randAES = mixinCryptor.generateAES(256);
        String castedReturn = originReturn instanceof String ? (String) originReturn : mapper.writeValueAsString(originReturn);
        HashMap<String, String> facade = new HashMap<>(2);
        String realAES = "";
        String keyData = "";
        String token, clientPub;
        switch (crypt.encryptMode()) {
            case RSA_AES_R_FUSE:
                token = (String) paramMap.get("token").e3;
                //取出pub_c
                clientPub = redisVar.redis.<String, String>boundHashOps(redisVar.redisTokenPubHash).get(token);
                //指定aes
                realAES = randAES;
                //加密aes
                keyData = mixinCryptor.rsaStr2StrPubEncrypt(randAES, clientPub);
                break;
            case RSA_AES_C_FUSE:
                token = (String) paramMap.get("token").e3;
                //取出pub_c
                clientPub = redisVar.redis.<String, String>boundHashOps(redisVar.redisTokenPubHash).get(token);
                //指定aes为aes_c
                realAES = redisVar.redis.<String, String>boundHashOps(redisVar.redisTokenSecHash).get(token);
                //加密aes
                keyData = mixinCryptor.rsaStr2StrPubEncrypt(randAES, clientPub);
                break;
            case AES_R_PLAIN:
                //指定aes
                realAES = randAES;
                //指定keyData
                keyData = realAES;
                break;
            case AES_C_FUSE:
                token = (String) paramMap.get("token").e3;
                //指定aes为aes_c
                realAES = redisVar.redis.<String, String>boundHashOps(redisVar.redisTokenSecHash).get(token);
                //指定keyData
                keyData = realAES;
                break;
            default:
                break;
        }
        String valData = mixinCryptor.aesStr2StrEncrypt(castedReturn, realAES);
        facade.put(crypt.keyIndex(), keyData);
        facade.put(crypt.dataIndex(), valData);
        return mapper.writeValueAsString(facade);
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
