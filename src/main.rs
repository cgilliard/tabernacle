#![no_std]
#![no_main]

mod syscall;

use core::panic::PanicInfo;

#[link(name = "c")]
unsafe extern "C" {}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    syscall::write(1, b"Hello, world!\n");
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    syscall::exit(1)
}
