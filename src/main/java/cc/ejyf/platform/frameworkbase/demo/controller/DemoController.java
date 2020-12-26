package cc.ejyf.platform.frameworkbase.demo.controller;

import cc.ejyf.platform.frameworkbase.aop.EncryptMode;
import cc.ejyf.platform.frameworkbase.aop.annotation.Crypt;
import cc.ejyf.platform.frameworkbase.aop.annotation.Decorate;
import cc.ejyf.platform.frameworkbase.env.RedisVar;
import cc.ejyf.platform.frameworkbase.util.MixinCryptor;
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
    @Crypt(hasBody = false, encryptMode = EncryptMode.AES_R_PLAIN)
    @Decorate
    @GetMapping("/getpub")
    public Object getServerPub(
//            HttpServletRequest request,
//            HttpServletResponse response
    ) {
        return redisVar.redis.<String, String>boundHashOps(redisVar.redisEncHash).get(redisVar.redisPubIndex);
    }

    @CrossOrigin
    @Crypt(encryptMode = EncryptMode.AES_R_PLAIN)
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
    @Crypt
    @Decorate
    @PostMapping("/uploadpub")
    public Object uploadPub(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(required = false) String token,
            @RequestBody HashMap<String, Object> body
    ) throws Exception {
        var map = Map.of("result", "upload success");
        redisVar.redis.<String, String>boundHashOps(redisVar.redisTokenPubHash).put(token, cryptor.reformatRSAKeyString((String) body.get("pubKey")));
        redisVar.redis.<String, String>boundHashOps(redisVar.redisTokenSecHash).put(token, (String) body.get("secKey"));
        return map;
    }

    @CrossOrigin
    @Crypt
    @Decorate
    @PostMapping("/normalcomm")
    public Object demoApi(
            HttpServletRequest request,
            HttpServletResponse response,
            @RequestHeader(required = false) String token,
            @RequestBody HashMap<String, Object> body
    ) throws Exception {
        System.out.println(body);
        var map = Map.of("ping", "pong", "pong", "ping");
        return map;
    }
}

