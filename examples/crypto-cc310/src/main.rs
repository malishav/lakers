#![no_std]
#![no_main]

use cortex_m_rt::entry;
use cortex_m_semihosting::debug::{self, EXIT_SUCCESS};
use defmt::info;
use defmt_rtt as _;
use panic_semihosting as _;

#[entry]
fn main() -> ! {
    info!("Running.");

    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);
    loop {}
}
