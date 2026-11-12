#[derive(zeroize::Zeroize)]
pub struct Secret([u8; 32]);
