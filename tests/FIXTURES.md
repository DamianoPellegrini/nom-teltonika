# Protocol fixture provenance

All fixtures are embedded as hexadecimal text in `tests/parser.rs`. Runtime tests
are offline. The examples were checked against the current official Teltonika
wiki on 2026-07-21.

| Constant | Protocol and codec | Official source and section | Byte origin | Expected result and assumptions |
| --- | --- | --- | --- | --- |
| `CODEC8` | TCP Codec 8 | [Data Sending Protocols, Codec 8, 1st example](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols#Codec_8) | Exact official hexadecimal example | One zero-coordinate AVL record, five IO elements, CRC `C7CF`. |
| `CODEC8_EXTENDED` | TCP Codec 8 Extended | [Data Sending Protocols, Codec 8 Extended example](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols#Codec_8_Extended) | Exact official hexadecimal example | One AVL record with two-byte IO identifiers/counts and no variable IO values. |
| `CODEC16` | TCP Codec 16 | [Data Sending Protocols, Codec 16 example](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols#Codec_16) | Exact official hexadecimal example | Two records with generation type and two-byte IO identifiers. |
| `CODEC12_COMMAND` | TCP Codec 12 | [Data Sending Protocols, Codec 12, getinfo request](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols#Codec_12) | Exact official hexadecimal example | One command containing ASCII `getinfo`; binary payload variants are generated from the documented widths and CRC coverage. |
| `UDP_CODEC8` | UDP Codec 8 | [Data Sending Protocols, Codec 8 over UDP example](https://wiki.teltonika-gps.com/view/Teltonika_Data_Sending_Protocols#Codec8_protocol_sending_over_UDP) | Exact official hexadecimal example | Channel packet ID `CAFE`, AVL packet ID `05`, public example IMEI, one AVL record. ACK is `0005CAFE010501`. |

Mutated malformed cases change only the field under test and recompute CRC when
the mutation must remain a completely delimited, otherwise valid frame. The
coordinate regression replaces official zero coordinates with extreme signed
wire values to prove preservation; it does not assign physical meaning to them.
