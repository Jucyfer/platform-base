package cc.ejyf.platform.frameworkbase.presist.batis.service;

import cc.ejyf.platform.frameworkbase.presist.batis.mapper.BasicMapper;
import cc.ejyf.platform.frameworkbase.presist.bean.ErrorRefBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class BasicService {
    @Autowired
    private BasicMapper basicMapper;

    /**
     * 获取异常参考映射表
     * @return
     */
    public ArrayList<ErrorRefBean> getErrorReferences(){
        return basicMapper.getErrorReferences();
    }
}
