package cc.ejyf.platform.frameworkbase.aop;
/*
 * 加密-统一格式-权限校验三件套。
 * 包含Cryptable、Decorate、Authorize三个注解。
 * 分别代表：加解密、报文统一格式化、权限校验三种处理逻辑
 * 目前的框架逻辑是，按照上述排列顺序，依次执行。
 * 即，先解密、再包装、然后鉴权；
 * 待业务controller处理完毕后，先包装，再加密，然后返回。
 *
 */