To get the PS Home client past the initial connection phase regardless of which version or region (SCEA, SCEE, SCEJ) you are running, you need to modify how MAPS.cs handles the MediusHelloRequest.

The Medius handshake is a "trust but verify" sequence. If the server is too picky about the AppID, it will reject the client before the login screen even appears.

How to Bypass/Relax the AppID Check
In the PSHome-MultiServer implementation of MAPS.cs, you are looking for the method that handles the MediusHelloRequest. To make the server universal, you generally want to implement the following logic:

1. Locate the Handshake Method
Find the section of code handling the MediusHelloRequest. It usually looks something like this:

C#
public void HandleHelloRequest(MediusHelloRequest request)
{
    // The server receives the request containing:
    // request.AppID
    // request.MajorVersion
    // request.MinorVersion
}
2. The "Universal" Response
Instead of checking if (request.AppID == 10684), you should force the server to accept the connection regardless of the incoming ID. You do this by sending back a MediusHelloResponse with a Success code.

In MAPS.cs, you would ensure the response looks like this:

C#
context.QueuePacket(new MediusHelloResponse
{
    MessageID = request.MessageID,
    ResponseCode = MediusResponseCode.Success, // This is the key
    MediusVersion = "v1.5", // Match what the client expects
});
Why this "Solves" the Connection Issue
AppID Independence: PS Home has dozens of AppIDs depending on the build (Beta, 1.0, 1.86, etc.) and the region. By ignoring the incoming AppID and just returning Success, the server becomes compatible with every dumped version of the game.

Version Spoofing: Some versions of the PS Home client are hardcoded to expect a specific string for the MediusVersion. If the server sends "2.1" but the client wants "1.5", the client might crash. In this code, you can manually set that string to ensure compatibility.

Risks of Bypassing
While this gets the client connected, keep in mind:

DME Differences: Even if you bypass the login check, the DME (Data Management Engine) might still fail if the client expects a different packet structure for movement or world sync.

Database Constraints: If your database is strictly tied to one region's account format, a client from another region might log in but fail to load their avatar.

[!TIP]
If you're editing MAPS.cs directly, look for the MediusAppId enum or constant. If you see a list of IDs, adding your client's ID to that list is the "clean" way; simply returning Success for everything is the "brute force" way

In the PSHome-MultiServer repository you linked, the "Hello" logic is actually handled slightly upstream in the Horizon framework's common packet handler, but the specific MAPS.cs file is where the session starts.

To bypass the AppID check and allow any PS Home version to connect, you need to ensure the MediusHelloRequest is intercepted and validated regardless of the ID.

The Code Modification
In the Horizon architecture used by this project, the validation usually happens in a packet handler. If you want to make it "universal," you would look for the HandleHelloRequest logic and modify it like this:

C#

// Locate this in your packet handler (often in the Horizon base or MAPS)
public void HandleHelloRequest(IMediusRequest request, IChannel channel)
{
    var helloRequest = (MediusHelloRequest)request;

    // THE FIX: Log the ID for debugging, but don't validate it.
    // Instead of: if (helloRequest.AppId != EXPECTED_ID) { fail; }
    // Just accept everything.
    
    channel.Queue(new MediusHelloResponse
    {
        MessageID = helloRequest.MessageID,
        ResponseCode = MediusResponseCode.Success, // Forces the client to proceed
        MediusVersion = "v1.5" // The version string Home typically looks for
    });
}

Why this works for PSHome
Handshake Completion: The client sends a "Hello" to see if the server speaks the same language. By returning Success, you stop the client from hanging at the "Connecting to Medius" screen.

AppID Neutrality: PS Home used different AppIDs for North America (SCEA), Europe (SCEE), and Japan (SCEJ). A "solved" server ignores these differences so a single server instance can host players from all regions simultaneously.

Session Transition: Once this packet is validated, the client immediately sends the MediusLoginRequest, which is handled by the Post(MediusLoginRequest request) method found in the MAPS.cs file you linked.

How to verify it's working
When you run the server with this bypass:

The Console: You should see a log entry similar to [MAPS] Hello from AppId: 10684 (or whatever ID your client uses).

The Client: The progress bar should move past the "Initialising" phase and prompt you for a username/password or move to the "Logging in" stage.

One potential "Gotcha"
Even if you bypass the Hello packet, the Login Packet in MAPS.cs might still check the AppID again. In the file you linked, you should look at the Post method for MediusLoginRequest.

[!NOTE]
If the login fails after the "Hello" is fixed, check if the AppID is being used as a key in your database. If the database only has accounts for AppID 10684, a Japan client (AppID 10695) will fail to find its account.

To find out exactly what your client is sending, you can add a simple "Logger" line inside the request handler. This is the best way to "solve" the server for your specific version of PS Home without guessing which ID you need.

In the MAPS.cs file (or the handler associated with it), you want to find the Post method for the login or the handshake. Adding this snippet will print the ID directly to your server console:

// Inside the MediusLoginRequest or HelloRequest handler
public void Post(MediusLoginRequest request)
{
    // ADD THIS LINE:
    Console.WriteLine($"[DEBUG] Client attempting login with AppID: {request.AppId}");

    // Rest of the existing logic...
}
To find out exactly what your client is sending, you can add a simple "Logger" line inside the request handler. This is the best way to "solve" the server for your specific version of PS Home without guessing which ID you need.

In the MAPS.cs file (or the handler associated with it), you want to find the Post method for the login or the handshake. Adding this snippet will print the ID directly to your server console:

C#
// Inside the MediusLoginRequest or HelloRequest handler
public void Post(MediusLoginRequest request)
{
    // ADD THIS LINE:
    Console.WriteLine($"[DEBUG] Client attempting login with AppID: {request.AppId}");

    // Rest of the existing logic...
}
Why this is the "Pro" way to solve it:
Different regions and builds of PS Home use different IDs. Here are the most common ones you'll see in the console:

10684: SCEA (North America)

10683: SCEE (Europe)

10695: SCEJ (Japan)

11051 / 11052: Various Beta or Dev builds

The "Universal" Fix in MAPS.cs
If you want to stop the server from caring about the AppID entirely, look for where the code checks request.AppId. You can "hard-fix" it by forcing the server to treat every incoming ID as the one your database expects.

Find the line where the AppID is validated and change it to:

C#
// Force the server to ignore the client's actual AppID and use 10684 (or your DB default)
var sessionAppId = 10684; 
What to look for next
Once you've bypassed the AppID check in the Hello and Login packets:

Check the MUIS: The client will then ask for the "Universe" (the list of worlds). If your MUIS.cs isn't configured with the same AppID logic, the world list will appear empty.

Check the Database: Ensure your Accounts table isn't restricted by AppID. Many PSHome databases have a column for AppID; if yours does, you might need to set it to NULL or make sure it matches what the client sends.




In the MAPS.cs file you linked, the logic is highly modular. Because this project is based on the Horizon framework, the "Hello" packet is often handled by the base Medius component, while the Login logic is handled directly in this file.

Here are the specific areas you need to look at:

1. The Login Packet Handling (AppID Check)
Scroll down to the Post method for MediusLoginRequest. It generally looks like this:

[ServiceNode(MediusRequestType.Login)]
public void Post(MediusLoginRequest request)
{
    // The server checks if the AppId is valid here
    if (Program.Settings.AppIds.Contains(request.AppId)) 
    {
        // Proceed with login...
    }
}

The "Solve": To make it universal, you would change that check to:
if (true) // Accept any AppId
Or, more safely, log the ID and then treat it as a valid one.

2. The Password/Account Validation
A few lines below the AppID check, you will find the database query:

var account = Program.Database.GetAccount(request.Username);

In the MAPS.cs file you linked, the logic is highly modular. Because this project is based on the Horizon framework, the "Hello" packet is often handled by the base Medius component, while the Login logic is handled directly in this file.

Here are the specific areas you need to look at:

1. The Login Packet Handling (AppID Check)
Scroll down to the Post method for MediusLoginRequest. It generally looks like this:

C#
[ServiceNode(MediusRequestType.Login)]
public void Post(MediusLoginRequest request)
{
    // The server checks if the AppId is valid here
    if (Program.Settings.AppIds.Contains(request.AppId)) 
    {
        // Proceed with login...
    }
}
The "Solve": To make it universal, you would change that check to:
if (true) // Accept any AppId
Or, more safely, log the ID and then treat it as a valid one.

2. The Password/Account Validation
A few lines below the AppID check, you will find the database query:

C#
var account = Program.Database.GetAccount(request.Username);
In many "unsolved" versions of this server, the database query also filters by AppID. You should check your Database.cs file to see if GetAccount is checking the AppId column. If it is, even if the MAPS server accepts the connection, the database will return "Account Not Found" because the ID doesn't match.

3. The "Hello" Handshake (If overridden)
While the MAPS.cs file you linked primarily focuses on the Post (Login) methods, the Hello handshake is often located in the MediusManager or a base MediusComponent.

If you want to verify if the Hello packet is working:

Look for MediusHelloRequest in the project search.

In the MediusHelloResponse being sent back, ensure the ResponseCode is strictly MediusResponseCode.Success.

How to use this file to "Solve" your server:
Match the Version: Ensure the MediusVersion string in the response matches what your PS Home build expects (e.g., v1.5).

Logging: Add Console.WriteLine($"Login attempt from AppID: {request.AppId}"); at the start of the Post method.

Rebuild: Since this is a .cs file, you must recompile the Horizon.SERVER project for these changes to take effect.


Does your current server console show "Login Request Received" when you try to connect, or does it stay completely silent? If it's silent, the problem is still in the "Hello" handshake (before it even gets to the code in MAPS.cs).
