package cc.ejyf.platform.frameworkbase.demo.controller.task;

import cc.ejyf.platform.frameworkbase.aop.util.MixinCryptor;
import cc.ejyf.platform.frameworkbase.env.RedisVar;
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
    private RedisVar redisVar;


    @Override
    public void run(String... args) throws Exception {
        var map = cryptor.generateRSA(512);
        var aes = cryptor.generateAES(256);
        redisVar.redis.<String,String>boundHashOps(redisVar.redisEncHash).put(redisVar.redisPubIndex, map.get("public"));
        redisVar.redis.<String,String>boundHashOps(redisVar.redisEncHash).put(redisVar.redisPriIndex, map.get("private"));
        redisVar.redis.<String,String>boundHashOps(redisVar.redisEncHash).put(redisVar.redisSecIndex, aes);
        System.out.println("keygen done.");
    }
}
