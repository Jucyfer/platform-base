package cc.ejyf.platform.frameworkbase.schedule;

import cc.ejyf.platform.frameworkbase.env.RedisVar;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

@Component
public class BasicSchedule {
    @Autowired
    private RedisVar redisVar;
    private DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

//    @Scheduled(cron = "* * * * * ?")
    public void cacheTime() {
        redisVar.redis.boundValueOps(redisVar.clockKey)
                .set(
                        LocalDateTime.now()
                                .atZone(ZoneId.systemDefault())
                                .format(formatter)
                );
    }
}
