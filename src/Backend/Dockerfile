FROM mcr.microsoft.com/dotnet/sdk:10.0.403 AS build

# MCR does not publish a 10.0.113 SDK image. Install the official SDK archive
# separately so global.json selects the same compiler as local development/CI.
# SHA-512 values: https://builds.dotnet.microsoft.com/dotnet/release-metadata/10.0/releases.json
ARG TARGETARCH
ENV DOTNET_ROOT=/opt/pam-dotnet \
    DOTNET_SDK_VERSION=10.0.113 \
    PATH=/opt/pam-dotnet:$PATH
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sdk_arch=x64; sdk_sha=1f2746d3684ef782c4308e056e709e9361802e082e401aff3760868125009a8aee2803ff3eeb87587dc60c766e5dc4f9bfd6051c660a85602cc892c31f72256d ;; \
      arm64) sdk_arch=arm64; sdk_sha=5131414303459d9752bef022c89ec681b70596e54456ee1c78f18a52fb9233fbf3fdb18b57d013d131f121fc643d8f47e7da0148525f95a982a9b74ac58a9011 ;; \
      *) echo "Unsupported SDK architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl --fail --location --retry 3 \
      "https://builds.dotnet.microsoft.com/dotnet/Sdk/$DOTNET_SDK_VERSION/dotnet-sdk-$DOTNET_SDK_VERSION-linux-$sdk_arch.tar.gz" \
      --output /tmp/pam-dotnet-sdk.tar.gz; \
    echo "$sdk_sha  /tmp/pam-dotnet-sdk.tar.gz" | sha512sum --check --status; \
    mkdir -p "$DOTNET_ROOT"; \
    tar -xzf /tmp/pam-dotnet-sdk.tar.gz -C "$DOTNET_ROOT"; \
    rm /tmp/pam-dotnet-sdk.tar.gz
WORKDIR /src

# Build from the repository root so shared MSBuild files are available.
COPY global.json .editorconfig Directory.Build.props Directory.Packages.props ./
RUN dotnet --version

# Copy project files first so dependency restore can be cached.
COPY src/Backend/Api/Api.csproj src/Backend/Api/
COPY src/Backend/Application/Application.csproj src/Backend/Application/
COPY src/Backend/Infrastructure/Infrastructure.csproj src/Backend/Infrastructure/
COPY src/Backend/Api/packages.lock.json src/Backend/Api/
COPY src/Backend/Application/packages.lock.json src/Backend/Application/
COPY src/Backend/Infrastructure/packages.lock.json src/Backend/Infrastructure/

WORKDIR /src/src/Backend
RUN dotnet restore Api/Api.csproj --locked-mode
COPY src/Backend/Migrator/Migrator.csproj Migrator/
COPY src/Backend/Migrator/packages.lock.json Migrator/
RUN dotnet restore Migrator/Migrator.csproj --locked-mode

COPY src/Backend/ ./
RUN dotnet publish Api/Api.csproj \
    -c Release \
    --no-restore \
    -o /app/publish \
    /p:UseAppHost=false

FROM build AS migrator-build
RUN dotnet publish Migrator/Migrator.csproj -c Release --no-restore \
    -o /app/migrator /p:UseAppHost=false

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS migrator
WORKDIR /app
COPY --from=migrator-build /app/migrator .
USER $APP_UID
ENTRYPOINT ["dotnet", "Migrator.dll"]

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /app/publish .
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

USER $APP_UID
ENTRYPOINT ["dotnet", "Api.dll"]
