#![no_std]
#![no_main]

use cortex_m_rt::entry;
use cortex_m_semihosting::debug::{self, EXIT_SUCCESS};
use defmt::info;
use defmt_rtt as _;
pub use nrf54l15_app_pac as pac;
use panic_semihosting as _;

#[entry]
fn main() -> ! {
    info!("Running.");

    let p = pac::Peripherals::take().unwrap();

    p.global_p2_s.pin_cnf(9).write(|w| w.dir().output());
    p.global_p2_s.outset().write(|w| w.pin9().set_bit());

    // exit via semihosting call
    debug::exit(EXIT_SUCCESS);
    loop {}
}
