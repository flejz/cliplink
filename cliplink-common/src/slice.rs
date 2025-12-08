#[macro_export]
macro_rules! slice {
    ($buf:tt[$offset:expr; $size:expr]) => {
        $buf[$offset..($offset + $size)]
    };
}
