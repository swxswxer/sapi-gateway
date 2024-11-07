package com.swx.sapigateway;

import com.swx.sapiclientsdk.utils.SignUtils;
import com.swx.sapicommon.model.entity.InterfaceCallLog;
import com.swx.sapicommon.model.entity.InterfaceInfo;
import com.swx.sapicommon.model.entity.User;
import com.swx.sapicommon.service.InnerInterfaceCallLogService;
import com.swx.sapicommon.service.InnerInterfaceInfoService;
import com.swx.sapicommon.service.InnerUserInterfaceInfoService;
import com.swx.sapicommon.service.InnerUserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
@Slf4j
public class CustomGlobalFilter implements GlobalFilter, Ordered {

    @DubboReference
    private InnerUserService innerUserService;
    @DubboReference
    private InnerInterfaceInfoService innerInterfaceInfoService;
    @DubboReference
    private InnerUserInterfaceInfoService innerUserInterfaceInfoService;
    @DubboReference
    private InnerInterfaceCallLogService innerInterfaceCallLogService;


    private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

//    private static final String INTERFACE_HOST = "http://120.79.135.199:29176/gateway";
    private static final String INTERFACE_HOST = "http://localhost:8090";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        //1.请求日志
        ServerHttpRequest request = exchange.getRequest();
        String path = INTERFACE_HOST+request.getPath().value();
        String method = request.getMethod().toString();
        log.info("请求唯一标识" + request.getId());
        log.info("请求路径" + path);
        log.info("请求方法" + method);
        log.info("请求参数" + request.getQueryParams());
        String sourceAddress = request.getLocalAddress().getHostString();
        log.info("请求来源地址" + sourceAddress);
        //3.用户鉴权（判断ak sk是否合法）
        ServerHttpResponse response = exchange.getResponse();
//        if (!IP_WHITE_LIST.contains(sourceAddress)) {
//            response.setStatusCode(HttpStatus.FORBIDDEN);
//            return response.setComplete();
//        }
        HttpHeaders headers = request.getHeaders();
        String accessKey = headers.getFirst("accessKey");
        String nonce = headers.getFirst("nonce");
        String timestamp = headers.getFirst("timestamp");
        String sign = headers.getFirst("sign");
        String body = headers.getFirst("body");
        // todo 实际情况应该是去数据库中查是否已分配给用户
        User invokeUser = null;
        try {
            invokeUser = innerUserService.getInvokeUser(accessKey);
        } catch (Exception e) {
            log.error("getInvokeUser error", e);
        }
        if (invokeUser == null) {
            return handleNoAuth(response);
        }

//        if (!"swx".equals(accessKey)) {
//            return handleNoAuth(response);
//        }
        if (Long.parseLong(nonce) > 10000L) {
            return handleNoAuth(response);
        }
        // 时间和当前时间不能超过 5 分钟
        Long currentTime = System.currentTimeMillis() / 1000;
        final Long FIVE_MINUTES = 60 * 5L;
        if ((currentTime - Long.parseLong(timestamp)) >= FIVE_MINUTES) {
            return handleNoAuth(response);
        }
        // 实际情况中是从数据库中查出 secretKey
        String secretKey = invokeUser.getSecretKey();
        String serverSign = SignUtils.genSign(nonce, secretKey);
        if (sign == null || !sign.equals(serverSign)) {
            return handleNoAuth(response);
        }
        //4.请求的模拟接口是否合法
        // 从数据库中查询模拟接口是否存在 以及请求方法是否匹配
        InterfaceInfo interfaceInfo = null;
        try {
            interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(path, method);
        } catch (Exception e) {
            log.error("getInterfaceInfo error", e);
        }
        if (interfaceInfo == null) {
            return handleNoAuth(response);
        }

//        转发请求
//        查询是否是新用户第一次调用 如果是 则增加记录 默认提供50次该接口调用额度 不是则判断是否有调用次数
        boolean isEmptyForUserInfaceInfo = innerUserInterfaceInfoService.isEmptyForUserInfaceInfo(interfaceInfo.getId(), invokeUser.getId());
        if (isEmptyForUserInfaceInfo) {
//return handleResponse(exchange, chain, interfaceInfo.getId(), invokeUser.getId());
            String realityUrl = interfaceInfo.getRealityUrl();
            if (realityUrl != null && !realityUrl.isEmpty()) {
                try {
                    // 动态设置新的转发 URI
                    URI newUri = URI.create(realityUrl);
                    // 修改请求的 URI，转发到 interfacePath
                    ServerHttpRequest modifiedRequest = request.mutate().uri(newUri).build();
                    ServerWebExchange modifiedExchange = exchange.mutate().request(modifiedRequest).build();
                    // 将修改后的请求继续交给下一个过滤器处理
//                    return chain.filter(modifiedExchange);
                    InterfaceInfo finalInterfaceInfo = interfaceInfo;
                    User finalInvokeUser = invokeUser;
                    //增加调用记录
                    InterfaceCallLog interfaceCallLog = new InterfaceCallLog();
                    interfaceCallLog.setUserId(invokeUser.getId());
                    interfaceCallLog.setInterfaceInfoId(finalInterfaceInfo.getId());
                    interfaceCallLog.setCallTime(LocalDateTime.now());
                    interfaceCallLog.setCallIp(sourceAddress);
                    return chain.filter(modifiedExchange).then(Mono.defer(() -> {
                        // 获取响应状态码，判断是否成功
                        HttpStatus statusCode = response.getStatusCode();
                        if (statusCode != null && statusCode.is2xxSuccessful()) {
                            // 5. 如果响应成功，增加调用次数
                            try {
//                                innerInterfaceInfoService.incrementInvokeCount(interfaceInfo.getId());
                                innerUserInterfaceInfoService.invokeCount(finalInterfaceInfo.getId(), finalInvokeUser.getId());
                                log.info("调用次数已增加 for interfaceId: " + finalInterfaceInfo.getId());
                            } catch (Exception e) {
                                log.error("incrementInvokeCount error", e);
                            }
                            //插入调用记录
                            interfaceCallLog.setStatus(0);
                            innerInterfaceCallLogService.insertInterfaceCallLog(interfaceCallLog);

                        } else {
                            log.warn("接口调用失败, 状态码: " + statusCode);
                            //插入调用记录
                            interfaceCallLog.setStatus(1);
                            interfaceCallLog.setErrorMessage(String.valueOf(statusCode));
                            innerInterfaceCallLogService.insertInterfaceCallLog(interfaceCallLog);
                        }
                        return Mono.empty();
                    }));


                } catch (Exception e) {
                    // 处理 URI 解析错误
                    return Mono.error(new IllegalArgumentException("Invalid interfacePath: " + realityUrl));
                }
            }
        }else {
            return handleNoAuth(response);
        }

        // 如果没有找到 interfacePath 头，继续正常的请求处理
        return chain.filter(exchange);
        //7.todo 调用成功 调用次数加一 invokeCount



       }


    /**
     * 处理响应
     *
     * @param exchange
     * @param chain
     * @return
     */
    public Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, long interfaceInfoId, long userId) {
        try {
            ServerHttpResponse originalResponse = exchange.getResponse();
            // 缓存数据的工厂
            DataBufferFactory bufferFactory = originalResponse.bufferFactory();
            // 拿到响应码
            HttpStatus statusCode = originalResponse.getStatusCode();
            if (statusCode == HttpStatus.OK) {
                // 装饰，增强能力
                ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
                    // 等调用完转发的接口后才会执行
                    @Override
                    public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
                        log.info("body instanceof Flux: {}", (body instanceof Flux));
                        if (body instanceof Flux) {
                            Flux<? extends DataBuffer> fluxBody = Flux.from(body);
                            // 往返回值里写数据
                            // 拼接字符串
                            return super.writeWith(
                                    fluxBody.map(dataBuffer -> {
                                        // 7. 调用成功，接口调用次数 + 1 invokeCount
                                        try {
                                            //记录调用
                                            //调用次数+1
                                            innerUserInterfaceInfoService.invokeCount(interfaceInfoId, userId);
                                            //增加调用记录

                                        } catch (Exception e) {
                                            log.error("invokeCount error", e);
                                        }
                                        byte[] content = new byte[dataBuffer.readableByteCount()];
                                        dataBuffer.read(content);
                                        DataBufferUtils.release(dataBuffer);//释放掉内存
                                        // 构建日志
                                        StringBuilder sb2 = new StringBuilder(200);
                                        List<Object> rspArgs = new ArrayList<>();
                                        rspArgs.add(originalResponse.getStatusCode());
                                        String data = new String(content, StandardCharsets.UTF_8); //data
                                        sb2.append(data);
                                        // 打印日志
                                        log.info("响应结果：" + data);
                                        return bufferFactory.wrap(content);
                                    }));
                        } else {
                            // 8. 调用失败，返回一个规范的错误码 增加调用记录 status = 1
                            log.error("<--- {} 响应code异常", getStatusCode());
                        }
                        return super.writeWith(body);
                    }
                };
                // 设置 response 对象为装饰过的
                return chain.filter(exchange.mutate().response(decoratedResponse).build());
            }
            return chain.filter(exchange); // 降级处理返回数据
        } catch (Exception e) {
            log.error("网关处理响应异常" + e);
            return chain.filter(exchange);
        }
    }


    private Mono<Void> handleNoAuth(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.FORBIDDEN);
        return response.setComplete();
    }

    private Mono<Void> handleInvokeError(ServerHttpResponse response) {
        response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
        return response.setComplete();
    }


    @Override
    public int getOrder() {
        return -1;
    }


}

