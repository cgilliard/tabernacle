use core::arch::asm;

const SYS_WRITE: usize = 1;
const SYS_EXIT_GROUP: usize = 231;

/// Issue a syscall with three arguments.
#[inline]
unsafe fn syscall3(n: usize, a1: usize, a2: usize, a3: usize) -> isize {
    let ret: isize;
    unsafe {
        asm!(
            "syscall",
            inlateout("rax") n => ret,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            out("rcx") _,   // clobbered by syscall
            out("r11") _,   // clobbered by syscall
            options(nostack),
        );
    }
    ret
}

pub fn write(fd: i32, buf: &[u8]) -> isize {
    unsafe { syscall3(SYS_WRITE, fd as usize, buf.as_ptr() as usize, buf.len()) }
}

pub fn exit(code: i32) -> ! {
    unsafe {
        asm!(
            "syscall",
            in("rax") SYS_EXIT_GROUP,
            in("rdi") code as usize,
            options(nostack, noreturn),
        );
    }
}
