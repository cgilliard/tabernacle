#![no_std]
#![no_main]

mod rt;
mod syscall;

#[link(name = "c")]
unsafe extern "C" {}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    syscall::write(1, b"Hello, world!\n");
    0
}
