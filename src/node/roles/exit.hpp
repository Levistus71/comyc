#pragma once

/*

1. Frame from relay
2. We get the app_data information: APP_Internal = APP_InternetProtocol + APP_TransportProtocol + APP_Encrypt(APP_Payload)
* APP_InternetProtocol contains client's local ip and port.
3. We can directly write APP_Internal to destination socket. The OS replaces client's local ip and port with Exit's information
before sending. After receiving the frame from the destination, the OS replaces the destination from the recevied frame to
client's local ip and port.

In short: the OS kinda understands that we are *routing* and are not a client. We don't need to change the raw
APP_InternetProtocol and replace it with our own ip. We need to maintain (client's local ip + port, circuit_id)
mapping in exit.

Caveat: We can't write the APP_Internal to the socket (connect() etc). We need to write the raw frame directly to the device.

*/

class Exit{
public:


private:
};