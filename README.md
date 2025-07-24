# 🔄 BitTorrent-Style File Sharing Client in C

This project implements a simplified **BitTorrent-style peer-to-peer file sharing client** written in C. It supports torrent parsing, peer communication, piece exchange, tracker interaction, and SHA-1 verification for data integrity.

The codebase is modular and includes support for threading, piece reservation, and error-tolerant peer handling — all built with socket-level networking.

---

## 📁 Project Structure

| File | Description |
|------|-------------|
| `main.c` | Entry point of the program. Parses the `.torrent` file, sets up the client, tracker connection, and peer listener. |
| `client.c` | Core logic: handles state, file I/O, bitfields, thread management, and communication flow. |
| `peer.c` | Peer protocol implementation (handshake, piece exchange, choke/unchoke, bitfield). |
| `peer_listener.c` | Listens for incoming peer connections and spins up handler threads. |
| `tracker_connection.c` | Manages tracker communication using HTTP GET and Bencode decoding. |
| `metainfo.c` | Parses `.torrent` files, extracts SHA-1 info hash, piece hashes, and metadata. |
| `bencode.c` | Decodes and encodes Bencode-formatted messages used by torrents and trackers. |

---

## 🧱 Building

To build the project, simply run:

```bash
make
```

This compiles all source files and generates the executable binaries

---

## ✅ Running Tests

You can verify the build and check for memory issues with:

```bash
make check          # Run standard tests
make check-valgrind # Run tests with Valgrind memory analysis
```

---

## 💡 Features

- 📦 **.torrent parser** with SHA-1 hashing
- 🧲 **Tracker client** using HTTP requests and libcurl
- 🤝 **Peer-to-peer protocol** with handshake, bitfield, and message types (e.g., `interested`, `have`, `request`, `piece`)
- 💾 **Chunked piece download/upload** with bitfield tracking
- 🔐 **Data integrity check** via SHA-1 hash for each piece
- 🧵 **Multithreaded** peer handling (listener + peer threads)
- ⚙️ **MPL support** for retry, choke, unchoke, and partial downloads

---

## 📘 Dependencies

Make sure you have the following libraries installed:

- `libcurl` (for tracker HTTP interaction)
- `libssl` / `libcrypto` (for SHA-1 hashing)
- POSIX threads 

You can install them using:

```bash
sudo apt install libcurl4-openssl-dev libssl-dev
```

---

## 📄 License

This project is for **educational and research purposes** and was developed as part of a computer networking course and personal learning.

---

## 👤 Author

Crafted with care to explore peer-to-peer networking, torrent protocols, and multi-threaded communication in C. If you use or build upon this project, feel free to reference it in your own work!

