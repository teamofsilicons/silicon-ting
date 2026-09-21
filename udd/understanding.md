This is Silicon Ting and it helps all other silicon apps to send notifications and for carbons & silicons to receive it. This is like the notification service on Android.

Someone (carbon or silicon) can login via IAM, and Ting asks for scopes to read about org details, and also get the list of apps of this org from Honeycomb. If this user has access to view thier orgs apps on honeycomb (could be possible that they have access to a certain org, and not for others).

On the sidebar, there is a org dropdown and at any given time only one org can be active. All things following have a org setup already (whichever the user connected).

There are two ways to use Ting: setup things for sending tings (apps) or setup things to receive tings (carbon or silicon)

# App Side
## New app registering Tings
If there are apps that can be fetched – then show a list of them. Inside each one, tings can be registered with a type, a description, and for [carbon and/or silicon]. all ting types are of the shape {appid}.{service}.{event in past tense} (tos>dm.msg.received), a description of when this ting is about, and if if it should also be sent to a carbon, silicon or both.

Tings are the primary way for apps to send a message to a silicon. Apps dont usually build their own notification / event delivery mechanism but instead relies on Ting.

## Carbons & Silicons using an App that uses Ting (OBO)
When a Carbon C or Silicon Si registeres on a app that uses Ting, it asks for a OBO that can be used to register this C or Si at Ting. Apps can not just send notifications to anyone. They must be allowed to ping them. This registration process is what allows them to.

User can later come to Ting directly and tune what all notifications they get & want to get.

Apps can also ask for the tings they have sent out to see their status (read or unread).

## Sending a Ting
the app sends this:
{
    type: "...",
    data: {...},
    metadata: {...},
    for: "{cid/sid}",
    key: {idempotency key},
}

as POST and in Authorization it sends a Proof Token that can be verified using IAM. Only send if it gets verified.

this is possible to do via POST request, or by establishing a persistent websocket for ultra-fast ting delivery.
Eg: Non-time sensitive tings can be POST and new messages can be sent over websockets.

server then maintains a cursor which gets moved when the ACK is sent back to the server by the receiver. until the ACK is recieved by the server that the notification has been delivered successfully, it is the responsibility of the server to maintain the cursor and send back the notification as a retry. Try ping-ponging with the receiver to keep the connection active.

The server maintains 2 ACKs per ting. Delivery ack and read ack. If the receiver received the ting, it replies back with a delivery ack. and once its sent to a silicon / carbon's local webhook, then it sends a read ack. if a delivery ack is received, then the server doesn't retry while that ws connection remains active. it retries only after the connection is killed without receiving a read ack.

if same silicon or carbon have registered on multiple webhooks, send that event to all of them

# User Side
## Receiving Tings
All tings are kept on ting's server unless there is a receiver attached to a carbon / silicon. A receiver is a websocket connection that registers one more carbons & silicon.

Situation:
[Ting Server]
    |
    |
[Local Daemon]
    |
    |
____|____
|   |   |
C   Si  C

A local daemon can be responsible for one or more than one carbons and silicon. Each receiver should be able to announce what all carbons and silicon it is listening to (via passing their access token while announcing responsibility). This is primarily to reduce network load on a system & server in case multiple carbons and silicons are running on the same system.

Worst case is on the website, where only one receiver for one carbon.

The local daemon takes in a local webhook url for each silicon/carbon to send the ting to.
all tings are sent in the following format:

{
    type: "ting type",
    data: {...},
    metadata: {...},
    key: ...,
}

it is then sent to the local listening url and a ACK is expected back to mark the ting as read.

## Configuring Tings
Silicons & carbons can log into ting and see what all tings they receive from which all apps and services.
They can then turn a service, or a event on and off.

During the registering phase, the carbon & silicon "for" that is set, is only the default but can be turned on and off.
Turning off a notification only turns off receiving notification by that silicon. All those are silently kept and never broadcasted. Only if a silicon wants to view them in their ting drawer, they can use the cli to view all their silent tings.


# Technical Specifications
Backend (Rust) > Rust Client > CLI + Daemon > Web App (Solid JS)

Backend is the brain, and the rust client is a stateless frontend to use it. Using this rust client, a CLI is built which is stateful with a persistent running Daemon. CLI is the primary interface for using ting. Both carbons and silicons use it. And then lastly we build a web app that is only for carbons. Webapp has functionality that is strictly a subset of cli.

In the CLI, ther could be a SILICON_HOME env variable that is where the base of the things that ting wants to store can be like access and refresh tokens. This is done because one system can have multiple Silicons running on it. This keeps their auth seperate. keep things inside .ting/

But, each one of these cli interfaces will be talking to the same daemon. This daemon establishes and pre-warmes a websocket connection with the ting server to receive notifications & forwarding it to the local webhook url (doesn't require auth). usually the local url looks like `http://{sid}.localhost/` but can be anything. When running commands, a silicon can only see its configurations. And can only connect or disconnect itsself via the CLI.

Do not create multiple daemons. Only one per system.

# Fallback and Recovery
If a ting could not be sent, then keep it in a unsent local db and keep retrying. Keep trying every 1min for 12hrs, if not received still, then mark that silicon as disconnected until the silicon establishes a reconnection again. See if the user of the webhook supports ping pong, in which case play it to ensure that the system is active and healthy instead of retrying to send the msg payload during failure. Play ping pong at a much higher freq. (5sec)

to connect and disconnect, CLI needs to support webhook and unhook commands.

If a silicon is dead, it should not stop the daemon from sending tings to other silicons and carbons of the system.


# Latency
Since there are only a few apps that would worry about latency, and would be over websocket->ting-server->daemon-websocket->webhook should be less than 100ms for p95. Its ok to get a few seconds for POST send method.

# Publishing
Ting will be a honeycomb app so follow all the specifications that it provides.
The backend will be on AWS (aws cli is logged in)
namecheap for all dna management and vercel for all frontend (cli logged in)

i am also logged into IAM cli as shubham as admin, make this as an app inside tos org as tos>ting

# Write modular code and dont abstract until it will be used atleast thrice.

# Storing Tings
Ting stores read or silent tings for one calendar month, and unread non-silent tings for three calendar months, measured from their original creation time in UTC.