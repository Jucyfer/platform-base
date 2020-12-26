package cc.ejyf.platform.frameworkbase.presist;

import cc.ejyf.platform.frameworkbase.presist.batis.service.BasicService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class PresistKit {
    @Autowired
    public BasicService basicService;
}
