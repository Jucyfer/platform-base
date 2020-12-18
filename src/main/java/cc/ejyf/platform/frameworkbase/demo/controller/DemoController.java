package cc.ejyf.platform.frameworkbase.demo.controller;

import cc.ejyf.platform.frameworkbase.aop.annotation.Authorize;
import cc.ejyf.platform.frameworkbase.aop.annotation.Cryptable;
import cc.ejyf.platform.frameworkbase.aop.annotation.Decorate;
import cc.ejyf.platform.frameworkbase.aop.util.MixinCryptor;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;


@RestController
public class DemoController {
    @Autowired
    private StringRedisTemplate redis;
    private ObjectMapper mapper = new ObjectMapper();
    @Value("{$server.encrypt.store.redis.key}")
    private String redisEncHash;
    @Value("{$server.encrypt.store.redis.key.pub.index}")
    private String redisPubIndex;
    @Value("{$server.encrypt.store.redis.token.pub.hash}")
    private String tokenPubHash;

    @Autowired
    private MixinCryptor cryptor;

    @CrossOrigin
    @Cryptable(aesDec = false, rsaPubEnc = false)
    @Decorate
    @GetMapping("/getpub")
    public String getServerPub() {
        return redis.<String, String>boundHashOps(redisEncHash).get(redisPubIndex);
    }

    @CrossOrigin
    @Cryptable(rsaPubEnc = false)
    @Decorate
    @PostMapping("/login")
    public String demoLogin(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(required = false) String token,
            @RequestBody HashMap<String, Object> body
    ) throws Exception {
        var map = Map.of("result", "login success", "code", "200", "token", "12345678");
        return mapper.writeValueAsString(map);
    }

    @CrossOrigin
    @Cryptable
    @Decorate
    @PostMapping("/uploadpub")
    public String uploadPub(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(required = false) String token,
            @RequestBody HashMap<String, Object> body
    ) throws Exception {
        var map = Map.of("result", "upload success", "code", "200");
        redis.<String, String>boundHashOps(tokenPubHash).put("12345678", cryptor.reformatRSAKeyString((String) body.get("pubKey")));
        return mapper.writeValueAsString(map);
    }

    @CrossOrigin
    @Cryptable
    @Decorate
    @PostMapping("/normalcomm")
    public String demoApi(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(required = false) String token,
            @RequestBody HashMap<String, Object> body
    ) throws Exception {
        var map = Map.of("ping", "pong", "pong", "ping");
        return mapper.writeValueAsString(map);
    }
}

