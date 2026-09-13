FROM mcr.microsoft.com/dotnet/sdk:10.0.102 AS build
WORKDIR /src
COPY global.json Directory.Build.props ./
COPY src/FileGuard.Core/FileGuard.Core.csproj src/FileGuard.Core/
COPY src/FileGuard.Cli/FileGuard.Cli.csproj src/FileGuard.Cli/
RUN dotnet restore src/FileGuard.Cli/FileGuard.Cli.csproj -r linux-x64
COPY src/FileGuard.Core/ src/FileGuard.Core/
COPY src/FileGuard.Cli/ src/FileGuard.Cli/
RUN dotnet publish src/FileGuard.Cli/FileGuard.Cli.csproj -c Release -r linux-x64 --self-contained false --no-restore -o /app

FROM mcr.microsoft.com/dotnet/runtime:10.0
WORKDIR /app
COPY --from=build /app/ ./
ENV DOTNET_EnableDiagnostics=0
ENTRYPOINT ["dotnet", "fileguard.dll"]
CMD ["--help"]
