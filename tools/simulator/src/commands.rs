//! Answers to Codec 12 commands, as an FMB device words them.
//!
//! Formats follow the examples of the Teltonika wiki pages "FMB getinfo",
//! "FMB getver", "FMB getstatus", "FMB getgps", and "FMB getio" (accessed
//! 2026-09-25), filled with the simulated device's state. Other commands get
//! no answer: the wiki doesn't say how a device answers a command it doesn't
//! know.

use crate::traffic::Traffic;

/// What a device reports about itself besides its vehicle.
pub(crate) struct DeviceState<'a> {
    pub(crate) imei: &'a str,
    pub(crate) mac: [u8; 6],
    /// When the device started, in milliseconds since the Unix epoch.
    pub(crate) init_millis: u64,
    /// Now, in milliseconds since the Unix epoch.
    pub(crate) now_millis: u64,
    /// Records the server acknowledged.
    pub(crate) sent_records: u64,
    pub(crate) traffic: &'a Traffic,
}

/// Returns the answer to `command`, or `None` for a command the simulator
/// doesn't know.
pub(crate) fn answer(command: &[u8], device: &DeviceState<'_>) -> Option<String> {
    let vehicle = device.traffic.vehicle();
    let moving = vehicle.speed_kph >= 1.0;
    let uptime = device.now_millis.saturating_sub(device.init_millis) / 1000;
    let command = std::str::from_utf8(command).ok()?.trim();
    Some(match command {
        // "RTC:2017/6/16 7:13 Init:2017/6/16 5:44 UpTime:4744s PWR:PwrVoltage
        // RST:0 GPS:2 SAT:0 TTFF:0 TTLF:0 NOGPS: 1:18 SR:0 FG:200 FL:0 SMS: 3
        // REC:42 MD:1 DB:0"
        "getinfo" => format!(
            "RTC:{} Init:{} UpTime:{uptime}s PWR:PwrVoltage RST:0 GPS:3 SAT:{} TTFF:28 \
             TTLF:0 NOGPS: 0:0 SR:{} FG:0 FL:0 SMS: 0 REC:{} MD:{} DB:0",
            minutes(device.now_millis),
            minutes(device.init_millis),
            vehicle.satellites,
            device.sent_records,
            device.traffic.queued(),
            u8::from(moving),
        ),
        // "Ver:02.00.01_06 GPS:AXN_3.80_3333_16070400,0000,, Hw:TFT100 Mod:1
        // IMEI:352094000000000 Init: 2017-6-16 5:54 Uptime: 16574
        // MAC:002E43912EF7 SPC:0(0) AXL:0 OBD:0 BL:1.6 BT:4"
        "getver" => {
            let (year, month, day, hour, minute, _) = civil(device.init_millis);
            let mac: String = device
                .mac
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect();
            format!(
                "Ver:03.28.07_00 GPS:AXN_5.10_3333 Hw:FMB920 Mod:13 IMEI:{} \
                 Init: {year}-{month}-{day} {hour}:{minute:02} Uptime: {uptime} MAC:{mac} \
                 SPC:1(0) AXL:1 OBD:0 BL:1.10 BT:4",
                device.imei,
            )
        }
        // "Data Link: 0 GPRS: 1 Phone: 0 SIM: 0 OP: 24602 Signal: 5 NewSMS: 0
        // Roaming: 0 SMSFull: 0 LAC: 1 Cell ID: 3055 NetType: 3 FwUpd:0"
        "getstatus" => format!(
            "Data Link: 1 GPRS: 1 Phone: 0 SIM: 0 OP: {} Signal: {} NewSMS: 0 Roaming: 0 \
             SMSFull: 0 LAC: {} Cell ID: {} NetType: 3 FwUpd:0",
            vehicle.operator, vehicle.gsm_signal, vehicle.area_code, vehicle.cell_id,
        ),
        // "GPS:1 Sat:0 Lat:54.666042 Long:25.225031 Alt:0 Speed:0 Dir:0
        // Date: 2017/6/16 Time: 12:52:30"
        "getgps" => {
            let (year, month, day, hour, minute, second) = civil(device.now_millis);
            format!(
                "GPS:1 Sat:{} Lat:{:.6} Long:{:.6} Alt:{:.0} Speed:{:.0} Dir:{:.0} \
                 Date: {year}/{month}/{day} Time: {hour}:{minute:02}:{second:02}",
                vehicle.satellites,
                vehicle.latitude,
                vehicle.longitude,
                vehicle.altitude,
                vehicle.speed_kph,
                vehicle.heading,
            )
        }
        // "DI1:0 DI2:0 DI3:0 AIN1:0 AIN2:0 DO1:0 DO2:0". On FMB devices DI1
        // is the ignition input.
        "getio" => format!(
            "DI1:{} DI2:0 DI3:0 AIN1:0 AIN2:0 DO1:0 DO2:0",
            u8::from(vehicle.ignition)
        ),
        _ => return None,
    })
}

/// Formats a time as the wiki's "2017/6/16 7:13".
fn minutes(millis: u64) -> String {
    let (year, month, day, hour, minute, _) = civil(millis);
    format!("{year}/{month}/{day} {hour}:{minute:02}")
}

/// Returns the UTC year, month, day, hour, minute, and second of `millis`
/// since the Unix epoch.
///
/// Days to a civil date as in Howard Hinnant's `civil_from_days`
/// (<https://howardhinnant.github.io/date_algorithms.html>).
fn civil(millis: u64) -> (i64, u32, u32, u32, u32, u32) {
    let seconds = (millis / 1000) as i64;
    let (days, of_day) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    let of_day = of_day as u32;
    (
        year,
        month,
        day,
        of_day / 3600,
        of_day / 60 % 60,
        of_day % 60,
    )
}

#[cfg(test)]
mod tests {
    use nom_teltonika::protocol::AvlCodec;

    use super::*;

    #[test]
    fn converts_times_to_utc_dates() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
        // 2017-06-16 12:52:30 UTC, the wiki's getgps example time.
        assert_eq!(civil(1_497_617_550_000), (2017, 6, 16, 12, 52, 30));
        assert_eq!(civil(951_782_400_000), (2000, 2, 29, 0, 0, 0));
    }

    #[test]
    fn answers_known_commands_in_the_wiki_formats() {
        let traffic = Traffic::new(AvlCodec::Codec8, 1, 1_000, 1, 1_497_617_550_000);
        let device = DeviceState {
            imei: "356307042441013",
            mac: [0x00, 0x2e, 0x43, 0x91, 0x2e, 0xf7],
            init_millis: 1_497_609_840_000,
            now_millis: 1_497_617_550_000,
            sent_records: 42,
            traffic: &traffic,
        };
        let getinfo = answer(b"getinfo", &device).unwrap();
        assert!(getinfo.starts_with("RTC:2017/6/16 12:52 Init:2017/6/16 10:44 UpTime:7710s"));
        assert!(getinfo.contains(" SR:42 "));
        let getver = answer(b"getver", &device).unwrap();
        assert!(getver.contains("IMEI:356307042441013 Init: 2017-6-16 10:44"));
        assert!(getver.contains("MAC:002E43912EF7"));
        assert!(
            answer(b"getgps", &device)
                .unwrap()
                .ends_with("Date: 2017/6/16 Time: 12:52:30")
        );
        assert!(
            answer(b"getstatus", &device)
                .unwrap()
                .starts_with("Data Link: 1 GPRS: 1")
        );
        assert_eq!(
            answer(b"getio", &device).unwrap(),
            "DI1:0 DI2:0 DI3:0 AIN1:0 AIN2:0 DO1:0 DO2:0"
        );
        assert_eq!(answer(b"setdigout 1", &device), None);
    }
}
