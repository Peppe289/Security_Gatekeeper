# ---- build -------------------------------------------------------------------------
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /workspace
COPY .mvn .mvn
COPY mvnw pom.xml ./
RUN ./mvnw -B -q dependency:go-offline
COPY src src
# Tests run in CI / locally with Docker available (Testcontainers); the image build only packages.
RUN ./mvnw -B -q -DskipTests package \
 && java -Djarmode=tools -jar target/security_gatekeeper-*.jar extract --layers --launcher --destination extracted

# ---- runtime -----------------------------------------------------------------------
FROM eclipse-temurin:17-jre-alpine
RUN addgroup -S gatekeeper && adduser -S -G gatekeeper -H gatekeeper
WORKDIR /app
# Layered copy: dependencies change rarely, so rebuilding after a code change is fast.
COPY --from=build /workspace/extracted/dependencies/ ./
COPY --from=build /workspace/extracted/spring-boot-loader/ ./
COPY --from=build /workspace/extracted/snapshot-dependencies/ ./
COPY --from=build /workspace/extracted/application/ ./
USER gatekeeper
EXPOSE 8080
ENV JAVA_TOOL_OPTIONS="-XX:MaxRAMPercentage=75 -XX:+ExitOnOutOfMemoryError"
HEALTHCHECK --interval=15s --timeout=3s --start-period=40s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/_gatekeeper/health || exit 1
ENTRYPOINT ["java", "org.springframework.boot.loader.launch.JarLauncher"]
