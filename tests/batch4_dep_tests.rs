#[test]
fn ml_dsa_crate_available() {
    // If this compiles, the dep is present
    let _ = std::mem::size_of::<ml_dsa::SigningKey<ml_dsa::MlDsa65>>();
}

#[cfg(feature = "qr")]
#[test]
fn qrcode_crate_available() {
    let qr = qrcode::QrCode::new(b"test").unwrap();
    assert!(qr.width() > 0);
}

#[cfg(feature = "qr")]
#[test]
fn image_crate_available() {
    let img = image::RgbImage::new(1, 1);
    assert_eq!(img.width(), 1);
}
