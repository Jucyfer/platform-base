package cc.ejyf.platform.frameworkbase.demo.controller.task;

import cc.ejyf.platform.frameworkbase.aop.util.MixinCryptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Order(1)
@Component
public class OnBootTask implements CommandLineRunner {
    @Autowired
    MixinCryptor cryptor;
    @Autowired
    StringRedisTemplate template;

    @Value("{$server.encrypt.store.redis.key}")
    private String redisEncHash;
    @Value("{$server.encrypt.store.redis.key.pub.index}")
    private String redisPubIndex;
    @Value("{$server.encrypt.store.redis.key.pri.index}")
    private String redisPriIndex;
    @Value("{$server.encrypt.store.redis.key.sec.index}")
    private String redisSecIndex;

    @Override
    public void run(String... args) throws Exception {
        var map = cryptor.generateRSA(512);
        var aes = cryptor.generateAES(256);
        template.<String,String>boundHashOps(redisEncHash).put(redisPubIndex, map.get("public"));
        template.<String,String>boundHashOps(redisEncHash).put(redisPriIndex, map.get("private"));
        template.<String,String>boundHashOps(redisEncHash).put(redisSecIndex, aes);
        System.out.println("keygen done.");
    }
}
