# Running the simulator

`tools/simulator` runs simulated Teltonika devices against a server and reports
how the server answered. It exits with status 0 if every answer was correct,
and with status 1 otherwise. `run --help` lists every option.

Each device behaves like an FMB device:

- It has a valid IMEI. `--tac` sets the first 8 digits.
- It takes records in real time from a vehicle that drives and parks.
- Its records have the IO elements an FMB003 sends.
- It sends an eventual record when the ignition changes.
- It sends again what the server doesn't acknowledge.
- It answers the Codec 12 commands `getinfo`, `getver`, `getstatus`, `getgps`,
  and `getio`.

`--interval-ms` sets the time between packets. `--records` sets the number of
records in each packet. The records are taken evenly over that time.

On macOS, the AirPlay Receiver uses port 5000, so the commands below use ports
5055 and 5056.

With many devices, raise the open file limit first, in every terminal. The
macOS default is 256.

```sh
ulimit -n 10240
```

## TCP

```sh
# Terminal 1: the Tokio example server.
cargo run --release --example tcp_server_tokio --features tokio -- 127.0.0.1:5055

# Terminal 2: 50 devices, 20 packets each.
cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5055 \
  --devices 50 --packets-per-device 20 --interval-ms 100 --records 5 --codec 8e
```

To inject faults, add `--faults`. The report counts the expected reactions
separately, so "unexpected" stays 0. The server logs errors for the connections
that are truncated on purpose.

```sh
cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5055 \
  --devices 20 --packets-per-device 50 --interval-ms 50 \
  --faults bad-crc,wrong-count,truncate,slow,disconnect --fault-rate 0.2
```

For a load test, discard the server's output. The server prints a line for each
packet.

```sh
cargo run --release --example tcp_server_tokio --features tokio -- 127.0.0.1:5055 > /dev/null

cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5055 \
  --devices 1000 --duration-s 60 --interval-ms 1000 --records 10 --ramp-up-ms 10000
```

The blocking server uses one thread for each connection.

```sh
cargo run --release --example tcp_server -- 127.0.0.1:5055
```

## UDP

```sh
cargo run --release --example udp_server -- 127.0.0.1:5056

cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5056 --transport udp \
  --devices 50 --packets-per-device 20 --interval-ms 100 --codec 16 --records 3
```

## Generating packets

`generate` writes deterministic packets to a file.

```sh
cargo run -p teltonika-simulator -- generate --codec 8 --records 2 --format bin --out file.bin
cargo run --example from_file
```

## Against Traccar

Run the simulator only against servers you own or are allowed to test.

Traccar listens for Teltonika devices on port 5027. Set it to register unknown
devices, so that it accepts the simulator's IMEIs.

```sh
docker run --rm -d --name traccar -p 5027:5027 -p 5027:5027/udp -p 8082:8082 \
  -e CONFIG_USE_ENVIRONMENT_VARIABLES=true -e DATABASE_REGISTER_UNKNOWN=true \
  traccar/traccar:latest

cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5027 \
  --devices 5 --packets-per-device 20 --interval-ms 50 --records 5 --codec 8e
```

Over TCP, the run has no unexpected answers.

Over UDP, every acknowledgment is reported as an "ack mismatch". Traccar
answers with packet ID `0000` instead of the datagram's packet ID, so the
devices keep sending the same datagram.

The `bad-crc` and `wrong-count` faults also give mismatches. Traccar checks
neither the CRC nor the second record count, so it acknowledges those packets.

Traccar can send a custom command, such as `getinfo`, while a device is
connected. The device answers it, and the answer appears in Traccar as a
command result.
