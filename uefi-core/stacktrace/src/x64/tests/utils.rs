pub fn hex_dump(mut addr: *const u8, len: usize) {
    unsafe {
        let mut remaining = len;

        println!(".------------------.-------------------------------------------------.----------------.");
        println!(
            "|                  |        {:016X}-{:016X}        | {:>8} Bytes |",
            addr as u64,
            addr.add(len) as u64,
            len
        );
        println!("|     Address      | 00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 |     Data       |");
        println!("|------------------+-------------------------------------------------+----------------|");
        while remaining > 0 {
            let line_length = std::cmp::min(16, remaining);

            print!("| {:016X} | ", addr as u64);
            for byte_index in 0..line_length {
                print!("{:02X} ", *addr.add(byte_index));
            }

            for _ in line_length..16 {
                print!("   ");
            }
            print!("|");

            for byte_index in 0..line_length {
                let ch = *addr.add(byte_index) as char;
                if (ch as u8) > 0x21 && (ch as u8) < 0x7F {
                    print!("{}", ch);
                } else {
                    print!(".");
                }
            }

            for _ in line_length..16 {
                print!(".");
            }

            println!("|");

            remaining -= line_length;
            addr = addr.add(line_length);
        }
        println!("'------------------'-------------------------------------------------'----------------'");
    }
}
