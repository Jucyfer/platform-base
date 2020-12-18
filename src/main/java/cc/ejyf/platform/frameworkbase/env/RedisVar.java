package cc.ejyf.platform.frameworkbase.env;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
public final class RedisVar {
    @Autowired
    public StringRedisTemplate redis;
    @Value("{$server.encrypt.store.redis.key}")
    public String redisEncHash;
    @Value("{$server.encrypt.store.redis.key.pub.index}")
    public String redisPubIndex;
    @Value("{$server.encrypt.store.redis.key.pri.index}")
    public String redisPriIndex;
    @Value("{$server.encrypt.store.redis.key.sec.index}")
    public String redisSecIndex;
    @Value("{$server.encrypt.store.redis.token.pub.hash}")
    public String redisTokenPubHash;
    @Value("${server.clock.store.redis.key}")
    public String clockKey;
}
