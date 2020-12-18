package cc.ejyf.platform.frameworkbase.demo.controller;

import cc.ejyf.platform.frameworkbase.aop.annotation.Cryptable;
import cc.ejyf.platform.frameworkbase.aop.annotation.Decorate;
import cc.ejyf.platform.frameworkbase.util.MixinCryptor;
import cc.ejyf.platform.frameworkbase.env.RedisVar;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;


@RestController
public class DemoController {
    @Autowired
    private RedisVar redisVar;
    @Autowired
    private MixinCryptor cryptor;

    @CrossOrigin
    @Cryptable(aesDec = false, rsaPubEnc = false)
    @Decorate
    @GetMapping("/getpub")
    public Object getServerPub() {
        return redisVar.redis.<String, String>boundHashOps(redisVar.redisEncHash).get(redisVar.redisPubIndex);
    }

    @CrossOrigin
    @Cryptable(rsaPubEnc = false)
    @Decorate
    @PostMapping("/login")
    public Object demoLogin(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(required = false) String token,
            @RequestBody HashMap<String, Object> body
    ) throws Exception {
        var map = Map.of("token", "12345678");
        return map;
    }

    @CrossOrigin
    @Cryptable
    @Decorate
    @PostMapping("/uploadpub")
    public Object uploadPub(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(required = false) String token,
            @RequestBody HashMap<String, Object> body
    ) throws Exception {
        var map = Map.of("result", "upload success");
        redisVar.redis.<String, String>boundHashOps(redisVar.redisTokenPubHash).put("12345678", cryptor.reformatRSAKeyString((String) body.get("pubKey")));
        return map;
    }

    @CrossOrigin
    @Cryptable
    @Decorate
    @PostMapping("/normalcomm")
    public Object demoApi(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(required = false) String token,
            @RequestBody HashMap<String, Object> body
    ) throws Exception {
        var map = Map.of("ping", "pong", "pong", "ping");
        return map;
    }
}

