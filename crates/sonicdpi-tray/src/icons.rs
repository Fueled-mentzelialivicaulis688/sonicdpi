//! Tray icons — generated procedurally so we don't ship binary assets.
//! Two states: idle (gray "off" dot) and active (green "on" dot).

use tray_icon::Icon;

const SIZE: u32 = 32;

pub fn active_icon() -> Icon {
    build_icon([0x2E, 0xCC, 0x71, 0xFF]) // bright green
}

pub fn idle_icon() -> Icon {
    build_icon([0x95, 0xA5, 0xA6, 0xFF]) // muted gray
}

fn build_icon(rgba_color: [u8; 4]) -> Icon {
    // 32×32 RGBA: anti-aliased filled circle on a transparent background.
    let mut buf = vec![0u8; (SIZE * SIZE * 4) as usize];
    let cx = SIZE as f32 / 2.0;
    let cy = SIZE as f32 / 2.0;
    let r = (SIZE as f32 / 2.0) - 1.5;

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 + 0.5 - cx;
            let dy = y as f32 + 0.5 - cy;
            let d = (dx * dx + dy * dy).sqrt();
            let alpha = if d <= r - 1.0 {
                1.0
            } else if d >= r {
                0.0
            } else {
                r - d
            };
            let idx = ((y * SIZE + x) * 4) as usize;
            buf[idx] = rgba_color[0];
            buf[idx + 1] = rgba_color[1];
            buf[idx + 2] = rgba_color[2];
            buf[idx + 3] = (rgba_color[3] as f32 * alpha) as u8;
        }
    }

    Icon::from_rgba(buf, SIZE, SIZE).expect("valid 32x32 RGBA buffer")
}
