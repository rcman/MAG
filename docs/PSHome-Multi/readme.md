To get the PSHome-MultiServer (Horizon) up and running from that repository, you’ll need to set up a development environment. Since this is a C# project, we’ll be using the .NET 8 SDK.

Here is the "fast-track" guide to compiling and launching it.

1. Prerequisites
Before you touch the code, make sure you have these installed:

.NET 8.0 SDK: (Critical: The GitHubProUser67 version specifically uses .NET 8 features for performance).

Git: To clone the repo.

Visual Studio 2022 (Community Edition is free) OR VS Code.

2. Clone and Prepare
Open your terminal (Command Prompt or PowerShell) and run:

Bash
git clone https://github.com/GitHubProUser67/PSHome-MultiServer.git
cd PSHome-MultiServer
3. The Compilation Process
You can build the whole solution at once. The "Horizon" server is the core part of the multi-server.

Using the Command Line (Fastest):

Bash
dotnet build
Using Visual Studio:

Open the .sln (Solution) file in the root folder.

Right-click the Solution in the Solution Explorer and select Restore NuGet Packages.

Press Ctrl+Shift+B to Build.

4. Configuration (The "Crucial" Step)
The server won't work out of the box until you tell it where to listen.

Navigate to the output folder (usually Servers/Horizon/SERVER/bin/Debug/net8.0).

Look for a config.json or settings.json file.

IP Address: Ensure the IP is set to 0.0.0.0 (to listen on all interfaces) or your local machine's LAN IP (e.g., 192.168.1.50).

Database: Ensure the connection string points to your local database (the repo usually comes with a default SQLite setup).

5. Running the Server
You need to start the Horizon component specifically. From the root directory:

Bash
dotnet run --project Servers/Horizon/SERVER/Horizon.SERVER.csproj
Troubleshooting the "Hello" Handshake
Once the server is running, watch the console carefully. When you boot your PS3/RPCS3:

If nothing happens: Your DNS isn't pointing to your PC, or a firewall is blocking port 10070 (the Medius port).

If it says "Hello Received" then stops: This is where that MAPS.cs fix we discussed comes in. It means the AppID or Version check failed.

If it says "Login Success": You’ve done it! The client will then move to the MUIS (Universe) stage.

Pro-Tip: The DNS Redirect
The PS3 client is hardcoded to look for myhome.playstation.net. You must redirect that URL to your computer's IP address using a custom DNS server (like BIND or a simple Windows DNS host) or the client will never find your Horizon server.
