#![no_std]
#![no_main]

mod rt;
mod syscall;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let code = main();
    syscall::exit(code);
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> i32 {
    syscall::write(1, b"Hello, world!\n");
    0
}
