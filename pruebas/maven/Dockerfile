FROM maven:3.9-eclipse-temurin-21-alpine@sha256:308cba8b638ed7e4658cea3f8399066219466211c805f6d5728c3c9c7614661b AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -B -q package -DskipTests

FROM eclipse-temurin:21-jre-alpine@sha256:ac05c3c42b7c2f1a52c9bd52f01041fa1958231b15ebeae7420429cbc5baf474
RUN apk upgrade --no-cache
COPY --from=build /app/target/prueba-maven-1.0.0.jar /app/app.jar
USER 65534
HEALTHCHECK --interval=30s --timeout=3s CMD java -version || exit 1
CMD ["java", "-cp", "/app/app.jar", "App"]
