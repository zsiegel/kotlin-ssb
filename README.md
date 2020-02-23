# Kotlin SSB
## WIP / EXPERIMENTAL / NOT FINISHED

A kotlin library for the [secure scuttlebutt protocol](https://ssbc.github.io/scuttlebutt-protocol-guide/).

I will try and livestream most of the work. Links to the videos are below.

- [Peer Discovery](https://www.youtube.com/watch?v=aBwNUX6BmNo)
- [Server Verify Hello](https://www.youtube.com/watch?v=aze6TeuX9WM)

### Testing
Currently testing against the [ssb-server](https://github.com/ssbc/ssb-server). Run it in an IDE for debugging 
or run it locally using the following.

```bash
ssb-server start --loggin.level=info
```

Once the server is running I can try and connect to it. 

### Status
Currently testing the client handshake.

### Capabilites

- [ ] Client Handshake
    - [x] Hello
    - [x] Read Hello
    - [x] Client Auth
    - [ ] Server Accept
- [ ] Server Handshake
    - [x] Verify Hello
- [ ] Local Discovery Service
- [ ] More, More, More