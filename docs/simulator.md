# Running the simulator

`tools/simulator` runs simulated Teltonika devices against a server and
reports how it answered. It exits with status 0 if the server answered as a
correct server does, 1 otherwise. See `run --help` for every option.

Each device behaves as an FMB device: a valid IMEI (`--tac` sets its first 8
digits), records taken in real time from a vehicle that drives and parks,
the IO elements an FMB003 sends, an eventual record when the ignition
changes, what isn't acknowledged sent again, and Codec 12 answers to
`getinfo`, `getver`, `getstatus`, `getgps`, and `getio` in the device's
words. `--interval-ms` is the time between packets; `--records` the records
in each, taken evenly over that time.

On macOS, port 5000 is taken by the AirPlay Receiver: the commands below use
5055 and 5056. With many devices, raise the open file limit first, in every
terminal (the macOS default is 256):

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

With faults. Expected reactions are counted apart, so "unexpected" stays 0;
the server logs errors for the connections truncated on purpose:

```sh
cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5055 \
  --devices 20 --packets-per-device 50 --interval-ms 50 \
  --faults bad-crc,wrong-count,truncate,slow,disconnect --fault-rate 0.2
```

Load, with the server's output discarded (it prints a line per packet):

```sh
cargo run --release --example tcp_server_tokio --features tokio -- 127.0.0.1:5055 > /dev/null

cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5055 \
  --devices 1000 --duration-s 60 --interval-ms 1000 --records 10 --ramp-up-ms 10000
```

The blocking server, one thread per connection:

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

```sh
cargo run -p teltonika-simulator -- generate --codec 8 --records 2 --format bin --out file.bin
cargo run --example from_file
```

## Against Traccar

Run it only against servers you own or may test. Traccar listens for
Teltonika devices on port 5027; register unknown devices so it accepts the
simulator's IMEIs:

```sh
docker run --rm -d --name traccar -p 5027:5027 -p 5027:5027/udp -p 8082:8082 \
  -e CONFIG_USE_ENVIRONMENT_VARIABLES=true -e DATABASE_REGISTER_UNKNOWN=true \
  traccar/traccar:latest

cargo run --release -p teltonika-simulator -- run --server 127.0.0.1:5027 \
  --devices 5 --packets-per-device 20 --interval-ms 50 --records 5 --codec 8e
```

TCP runs clean. Over UDP every acknowledgment is an "ack mismatch": Traccar
answers with packet ID `0000` instead of echoing the datagram's, so the
devices keep sending the same datagram. Faults `bad-crc` and `wrong-count`
also give mismatches: Traccar checks neither the CRC nor the second record
count, so it acknowledges those packets.

Commands sent from Traccar (a custom command such as `getinfo`, while the
device is connected) are answered and show up as command results.
