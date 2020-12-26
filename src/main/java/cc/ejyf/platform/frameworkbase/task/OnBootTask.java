package cc.ejyf.platform.frameworkbase.task;

import cc.ejyf.platform.frameworkbase.env.RedisVar;
import cc.ejyf.platform.frameworkbase.presist.PresistKit;
import cc.ejyf.platform.frameworkbase.util.MixinCryptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.stereotype.Component;

import java.util.HashMap;

@Order(1)
@Component
public class OnBootTask implements CommandLineRunner {
    @Autowired
    MixinCryptor cryptor;
    @Autowired
    private RedisVar redisVar;
    @Autowired
    private PresistKit presistKit;
    private Logger logger = LoggerFactory.getLogger(OnBootTask.class);


    @Override
    public void run(String... args) throws Exception {
        generateKeys();
        initErrorRef();
    }

    //生成密钥
    private void generateKeys() throws Exception {
        var map = cryptor.generateRSA(512);
        var aes = cryptor.generateAES(256);
        redisVar.redis.<String, String>boundHashOps(redisVar.redisEncHash).put(redisVar.redisPubIndex, map.get("public"));
        redisVar.redis.<String, String>boundHashOps(redisVar.redisEncHash).put(redisVar.redisPriIndex, map.get("private"));
        redisVar.redis.<String, String>boundHashOps(redisVar.redisEncHash).put(redisVar.redisSecIndex, aes);
        logger.info("keygen done.");
    }

    //填充初始化错误代码映射表
    private void initErrorRef() throws Exception {
        HashMap<String, String> errMsgCodeRef = new HashMap<>();
        HashMap<String, String> errMsgWrapRef = new HashMap<>();
        presistKit.basicService.getErrorReferences().forEach(
                e -> {
                    errMsgCodeRef.put(e.getExceptionClassName(), e.getErrorCode());
                    errMsgWrapRef.put(e.getExceptionClassName(), e.getExceptionMessage());
                }
        );
        HashOperations<String, String, String> hashOperations = redisVar.redis.opsForHash();

        redisVar.redis.delete(redisVar.errCodeMappingHash);
        hashOperations.putAll(redisVar.errCodeMappingHash, errMsgCodeRef);

        redisVar.redis.delete(redisVar.errMsgMappingHash);
        hashOperations.putAll(redisVar.errMsgMappingHash, errMsgWrapRef);
        logger.info("error Mapping done.");
    }
}
