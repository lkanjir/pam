FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Build from the repository root so shared MSBuild files are available.
COPY Directory.Build.props Directory.Packages.props ./

# Copy project files first so dependency restore can be cached.
COPY src/Backend/Api/Api.csproj src/Backend/Api/
COPY src/Backend/Application/Application.csproj src/Backend/Application/
COPY src/Backend/Infrastructure/Infrastructure.csproj src/Backend/Infrastructure/

WORKDIR /src/src/Backend
RUN dotnet restore Api/Api.csproj
COPY src/Backend/Migrator/Migrator.csproj Migrator/
RUN dotnet restore Migrator/Migrator.csproj

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
