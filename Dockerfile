# Docker 镜像构建
FROM openjdk:11-jre-slim


COPY ./target/sapi-gateway-0.0.1-SNAPSHOT.jar /tmp/sapi-gateway-0.0.1-SNAPSHOT.jar

# 暴露端口
EXPOSE 8090

# 指定容器启动时运行的指令
ENTRYPOINT ["java", "-jar", "/tmp/sapi-gateway-0.0.1-SNAPSHOT.jar"]
