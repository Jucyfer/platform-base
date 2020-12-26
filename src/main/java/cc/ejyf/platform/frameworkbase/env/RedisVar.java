package cc.ejyf.platform.frameworkbase.env;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

@Component
public final class RedisVar {
    @Autowired
    public StringRedisTemplate redis;
    @Value("${server.encrypt.store.redis.key.hash}")
    public String redisEncHash;
    @Value("${server.encrypt.store.redis.key.pub.index}")
    public String redisPubIndex;
    @Value("${server.encrypt.store.redis.key.pri.index}")
    public String redisPriIndex;
    @Value("${server.encrypt.store.redis.key.sec.index}")
    public String redisSecIndex;
    @Value("${server.encrypt.store.redis.token.pub.hash}")
    public String redisTokenPubHash;
    @Value("${server.encrypt.store.redis.token.sec.hash}")
    public String redisTokenSecHash;
    @Value("${server.clock.store.redis.key}")
    public String clockKey;
    @Value("${server.error.code.mapping.store.redis.hash}")
    public String errCodeMappingHash;
    @Value("${server.error.msg.mapping.store.redis.hash}")
    public String errMsgMappingHash;

}
