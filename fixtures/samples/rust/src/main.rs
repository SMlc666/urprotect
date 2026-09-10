fn main() {
    let value: u64 = 0x0123_4567_89ab_cdef;
    println!("urprotect-fixture:rust");
    println!("checksum={:016x}", value.rotate_left(13));
}
