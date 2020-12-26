package cc.ejyf.platform.frameworkbase.presist.batis.mapper;

import cc.ejyf.platform.frameworkbase.presist.bean.ErrorRefBean;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
@Mapper
public interface BasicMapper {
    @Select("select exceptionClassName,exceptionMessage,errorCode from ERROR_REF")
    ArrayList<ErrorRefBean> getErrorReferences();
}
