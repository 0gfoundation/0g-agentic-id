//! Pixel-art avatar generator — deterministic 16×16 SVG from a 32-byte seed.
//!
//! Faithful port of the "Pretty SHA" JavaScript algorithm. The seed is
//! interpreted as a flat byte stream that drives:
//!   - palette derivation (OKLCH → linear sRGB → gamma sRGB → hex)
//!   - top-level type pick (person / animal / plant / monster / robot)
//!   - sub-type selection and accessory toggles
//!   - bit-driven texture overlay reading the unused tail of the hash
//!
//! Public API: `seed_to_data_url(seed)` returns a `data:image/svg+xml;base64,…`
//! URL suitable for embedding in AgentCard.image.

use base64::Engine as _;

const GS: usize = 16;

/// Cell value in the 16×16 grid: `None` = transparent (shows bg), or a
/// palette index 0..=8.
type Grid = [[Option<u8>; GS]; GS];

fn new_grid() -> Grid {
    [[None; GS]; GS]
}

/// Set a single pixel. Bounds-checked (matches JS `sp`).
fn sp(g: &mut Grid, c: i32, r: i32, v: u8) {
    if r >= 0 && r < GS as i32 && c >= 0 && c < GS as i32 {
        g[r as usize][c as usize] = Some(v);
    }
}

/// Fill rectangle (matches JS `fr`).
fn fr(g: &mut Grid, c: i32, r: i32, w: i32, h: i32, v: u8) {
    for i in r..r + h {
        for j in c..c + w {
            sp(g, j, i, v);
        }
    }
}

// ── OKLCH → linear sRGB → gamma sRGB → hex ──────────────────────────────
fn oklch_to_hex(l: f64, c: f64, h_deg: f64) -> String {
    let h_norm = ((h_deg % 360.0) + 360.0) % 360.0;
    let h = h_norm * std::f64::consts::PI / 180.0;
    let a = c * h.cos();
    let b = c * h.sin();
    let l_ = l + 0.3963377774 * a + 0.2158037573 * b;
    let m_ = l - 0.1055613458 * a - 0.0638541728 * b;
    let s_ = l - 0.0894841775 * a - 1.2914855480 * b;
    let l3 = l_ * l_ * l_;
    let m3 = m_ * m_ * m_;
    let s3 = s_ * s_ * s_;
    let r = 4.0767416621 * l3 - 3.3077115913 * m3 + 0.2309699292 * s3;
    let g = -1.2684380046 * l3 + 2.6097574011 * m3 - 0.3413193965 * s3;
    let bv = -0.0041960863 * l3 - 0.7034186147 * m3 + 1.7076147010 * s3;
    let gm = |x: f64| -> f64 {
        if x <= 0.003_130_8 {
            12.92 * x
        } else {
            1.055 * x.max(0.0).powf(1.0 / 2.4) - 0.055
        }
    };
    let to8 = |x: f64| -> u8 { (gm(x) * 255.0).round().clamp(0.0, 255.0) as u8 };
    format!("#{:02x}{:02x}{:02x}", to8(r), to8(g), to8(bv))
}

fn make_bg(b: &[u8; 32]) -> String {
    let h = (b[0] as f64 / 255.0) * 360.0;
    let ch = 0.08 + (b[2] as f64 / 255.0) * 0.10;
    oklch_to_hex(0.92, ch * 0.07, h)
}

/// 9-entry palette. Indexes:
/// 0 body / 1 trim / 2 skin / 3 shadow / 4 accent / 5 white / 6 deep /
/// 7 soft / 8 metal.
fn make_palette(b: &[u8; 32]) -> [String; 9] {
    let h = (b[0] as f64 / 255.0) * 360.0;
    let sc = (b[1] % 4) as usize;
    let ch = 0.08 + (b[2] as f64 / 255.0) * 0.10;
    let l0 = 0.50 + (b[3] as f64 / 255.0) * 0.20;
    let offsets = [[180.0, 180.0], [120.0, 240.0], [30.0, -30.0], [150.0, 210.0]];
    let o1 = offsets[sc][0];
    let o2 = offsets[sc][1];
    let sk_l = 0.72 + (b[4] as f64 / 255.0) * 0.14;
    let sk_h = 22.0 + (b[4] as f64 / 255.0) * 28.0;
    [
        oklch_to_hex(l0, ch, h),
        oklch_to_hex(l0 * 0.9, ch, h + o1),
        oklch_to_hex(sk_l, 0.045, sk_h),
        oklch_to_hex(0.18, 0.04, h),
        oklch_to_hex(l0 * 0.85, ch * 1.3, h + o2),
        "#ffffff".to_string(),
        oklch_to_hex(l0 * 0.60, ch * 0.9, h + o1 + 20.0),
        oklch_to_hex(0.91, ch * 0.05, h + 30.0),
        oklch_to_hex(0.70, ch * 0.55, h + o2 + 15.0),
    ]
}

// ── Person ──────────────────────────────────────────────────────────────
fn gen_person(b: &[u8; 32], g: &mut Grid) {
    let hair_v = b[7] % 8;
    let hat_type = (b[7] >> 4) % 4;
    let face_v = b[8] % 4;
    let eye_v = (b[8] >> 4) % 3;
    let shirt_v = b[9] % 6;
    let pants_v = (b[9] >> 4) % 4;
    let hat = b[10] > 180;
    let glasses = b[11] > 215;
    let tie = b[12] > 210;
    let scarf = b[13] > 225;
    let blush = b[14] > 180;
    let badge = b[15] > 210;
    let colored_iris = b[16] > 200;
    let boots = b[17] > 190;
    let belt = b[18] > 200;
    let freckles = b[19] > 210;
    let pocket = b[20] > 200;

    // Hair
    if !hat {
        match hair_v {
            0 => fr(g, 4, 2, 8, 1, 0),
            1 => {
                fr(g, 4, 1, 8, 1, 0);
                sp(g, 4, 2, 0);
                sp(g, 11, 2, 0);
                sp(g, 4, 3, 0);
                sp(g, 11, 3, 0);
            }
            2 => {
                fr(g, 4, 1, 8, 2, 0);
                fr(g, 4, 3, 1, 3, 0);
                fr(g, 11, 3, 1, 3, 0);
            }
            3 => {
                fr(g, 4, 1, 8, 1, 0);
                fr(g, 4, 2, 1, 7, 0);
                fr(g, 11, 2, 1, 7, 0);
            }
            4 => {
                sp(g, 5, 1, 0);
                sp(g, 7, 0, 0);
                sp(g, 9, 1, 0);
                fr(g, 4, 2, 8, 1, 0);
                sp(g, 4, 3, 0);
                sp(g, 11, 3, 0);
            }
            5 => {
                sp(g, 4, 0, 0);
                sp(g, 6, 0, 0);
                sp(g, 8, 0, 0);
                sp(g, 10, 0, 0);
                sp(g, 5, 1, 0);
                sp(g, 7, 1, 0);
                sp(g, 9, 1, 0);
                fr(g, 4, 2, 8, 1, 0);
                sp(g, 4, 3, 0);
                sp(g, 11, 3, 0);
            }
            6 => {
                fr(g, 2, 0, 12, 1, 0);
                fr(g, 2, 1, 12, 2, 0);
                fr(g, 3, 3, 10, 1, 0);
                sp(g, 4, 4, 0);
                sp(g, 11, 4, 0);
            }
            _ => {
                // 7 — bun
                fr(g, 5, 0, 6, 2, 0);
                fr(g, 4, 2, 8, 1, 0);
                sp(g, 4, 3, 0);
                sp(g, 11, 3, 0);
                sp(g, 4, 4, 0);
                sp(g, 11, 4, 0);
            }
        }
    } else {
        match hat_type {
            0 => {
                fr(g, 4, 1, 8, 3, 0);
                fr(g, 3, 4, 11, 1, 6);
                fr(g, 4, 4, 8, 1, 0);
            }
            1 => {
                fr(g, 5, 0, 6, 4, 0);
                fr(g, 4, 4, 8, 1, 6);
                if b[21] > 128 {
                    fr(g, 5, 3, 6, 1, 4);
                }
            }
            2 => {
                fr(g, 4, 0, 8, 4, 0);
                fr(g, 3, 3, 10, 1, 0);
                sp(g, 7, 0, 4);
                sp(g, 8, 0, 4);
            }
            _ => {
                fr(g, 4, 2, 8, 2, 4);
                sp(g, 4, 0, 4);
                sp(g, 6, 0, 4);
                sp(g, 8, 0, 4);
                sp(g, 10, 0, 4);
                sp(g, 5, 1, 4);
                sp(g, 7, 1, 4);
                sp(g, 9, 1, 4);
                sp(g, 11, 1, 4);
                sp(g, 5, 0, 5);
                sp(g, 8, 0, 5);
                sp(g, 11, 0, 5);
            }
        }
        sp(g, 4, 5, 0);
        sp(g, 11, 5, 0);
    }

    // Face
    fr(g, 4, 2, 8, 6, 2);

    // Eyes
    match eye_v {
        0 => {
            sp(g, 5, 3, 5);
            sp(g, 6, 3, 3);
            sp(g, 9, 3, 5);
            sp(g, 10, 3, 3);
        }
        1 => {
            fr(g, 5, 3, 2, 2, 5);
            fr(g, 9, 3, 2, 2, 5);
            sp(g, 6, 4, 3);
            sp(g, 10, 4, 3);
        }
        _ => {
            sp(g, 5, 3, 3);
            fr(g, 5, 3, 2, 1, 5);
            sp(g, 9, 3, 3);
            fr(g, 9, 3, 2, 1, 5);
        }
    }
    if colored_iris {
        sp(g, 5, 3, 4);
        sp(g, 9, 3, 4);
    }

    sp(g, 7, 4, 3);
    sp(g, 8, 4, 3);

    match face_v {
        0 => {
            sp(g, 6, 5, 3);
            sp(g, 7, 6, 3);
            sp(g, 8, 6, 3);
            sp(g, 9, 5, 3);
        }
        1 => fr(g, 6, 5, 4, 1, 3),
        2 => {
            sp(g, 6, 5, 3);
            sp(g, 9, 5, 3);
            fr(g, 7, 5, 2, 2, 5);
            sp(g, 7, 6, 3);
            sp(g, 8, 6, 3);
        }
        _ => {
            sp(g, 7, 5, 3);
            sp(g, 8, 5, 3);
            sp(g, 9, 6, 3);
        }
    }

    if blush {
        sp(g, 4, 5, 4);
        sp(g, 11, 5, 4);
    }
    if freckles {
        sp(g, 5, 5, 3);
        sp(g, 6, 5, 3);
        sp(g, 9, 5, 3);
        sp(g, 10, 5, 3);
    }
    if glasses {
        sp(g, 5, 3, 4);
        sp(g, 7, 3, 4);
        sp(g, 5, 4, 4);
        sp(g, 7, 4, 4);
        sp(g, 8, 3, 4);
        sp(g, 9, 3, 4);
        sp(g, 11, 3, 4);
        sp(g, 9, 4, 4);
        sp(g, 11, 4, 4);
        sp(g, 4, 3, 4);
        sp(g, 12, 3, 4);
    }

    // Shirt
    match shirt_v {
        0 => fr(g, 4, 8, 8, 4, 1),
        1 => {
            fr(g, 4, 8, 8, 4, 1);
            let mut r = 9;
            while r < 12 {
                fr(g, 4, r, 8, 1, 4);
                r += 2;
            }
        }
        2 => {
            fr(g, 4, 8, 8, 4, 1);
            sp(g, 7, 9, 2);
            sp(g, 8, 9, 2);
        }
        3 => {
            fr(g, 4, 8, 8, 4, 1);
            sp(g, 7, 9, 5);
            sp(g, 8, 9, 5);
            sp(g, 7, 10, 5);
            sp(g, 8, 10, 5);
            sp(g, 7, 11, 5);
            sp(g, 8, 11, 5);
        }
        4 => {
            fr(g, 4, 8, 8, 4, 1);
            sp(g, 4, 8, 6);
            sp(g, 5, 8, 6);
            sp(g, 10, 8, 6);
            sp(g, 11, 8, 6);
            sp(g, 4, 9, 6);
            sp(g, 11, 9, 6);
            fr(g, 6, 10, 4, 2, 6);
        }
        _ => {
            fr(g, 5, 8, 6, 4, 1);
            fr(g, 2, 9, 2, 3, 2);
            fr(g, 12, 9, 2, 3, 2);
        }
    }
    if shirt_v != 5 {
        fr(g, 2, 9, 2, 3, 1);
        fr(g, 12, 9, 2, 3, 1);
    }
    fr(g, 2, 12, 2, 1, 2);
    fr(g, 12, 12, 2, 1, 2);
    if shirt_v < 4 {
        sp(g, 7, 8, 5);
        sp(g, 8, 8, 5);
        sp(g, 6, 9, 5);
        sp(g, 9, 9, 5);
    }
    if tie && !scarf {
        fr(g, 7, 9, 2, 3, 4);
        sp(g, 7, 12, 4);
        sp(g, 8, 12, 4);
    }
    if scarf {
        fr(g, 5, 8, 6, 2, 4);
    }
    if badge {
        sp(g, 5, 10, 4);
        sp(g, 5, 11, 3);
    }
    if pocket {
        fr(g, 4, 10, 2, 2, 6);
    }

    // Pants
    match pants_v {
        0 => {
            fr(g, 4, 12, 8, 1, 6);
            fr(g, 4, 13, 3, 3, 6);
            fr(g, 9, 13, 3, 3, 6);
        }
        1 => {
            fr(g, 4, 12, 8, 2, 6);
            fr(g, 4, 13, 3, 1, 6);
            fr(g, 9, 13, 3, 1, 6);
            fr(g, 4, 14, 3, 2, 2);
            fr(g, 9, 14, 3, 2, 2);
        }
        2 => {
            fr(g, 4, 12, 8, 1, 6);
            fr(g, 3, 13, 10, 2, 6);
            fr(g, 3, 15, 4, 1, 2);
            fr(g, 9, 15, 4, 1, 2);
        }
        _ => {
            fr(g, 4, 12, 8, 1, 6);
            fr(g, 4, 13, 3, 3, 6);
            fr(g, 9, 13, 3, 3, 6);
            sp(g, 6, 8, 6);
            sp(g, 7, 8, 6);
            sp(g, 8, 8, 6);
            sp(g, 9, 8, 6);
            sp(g, 6, 9, 6);
            sp(g, 9, 9, 6);
        }
    }
    if belt {
        fr(g, 4, 12, 8, 1, 3);
        sp(g, 7, 12, 3);
        sp(g, 8, 12, 3);
    }
    fr(g, 3, 15, 4, 1, 3);
    fr(g, 9, 15, 4, 1, 3);
    if boots {
        fr(g, 3, 14, 4, 1, 3);
        fr(g, 9, 14, 4, 1, 3);
    }
}

// ── Animals ─────────────────────────────────────────────────────────────
fn gen_animal(b: &[u8; 32], g: &mut Grid) {
    match b[7] % 10 {
        0 => gen_cat(b, g),
        1 => gen_rabbit(b, g),
        2 => gen_bear(b, g),
        3 => gen_fox(b, g),
        4 => gen_penguin(b, g),
        5 => gen_frog(b, g),
        6 => gen_dog(b, g),
        7 => gen_wolf(b, g),
        8 => gen_duck(b, g),
        _ => gen_panda(b, g),
    }
}

fn gen_cat(b: &[u8; 32], g: &mut Grid) {
    sp(g, 3, 0, 0);
    sp(g, 12, 0, 0);
    fr(g, 2, 1, 3, 1, 0);
    fr(g, 11, 1, 3, 1, 0);
    sp(g, 3, 1, 4);
    sp(g, 12, 1, 4);
    fr(g, 2, 2, 3, 1, 0);
    fr(g, 11, 2, 3, 1, 0);
    fr(g, 3, 2, 10, 7, 0);
    fr(g, 4, 3, 8, 5, 7);
    sp(g, 5, 4, 4);
    sp(g, 6, 4, 3);
    sp(g, 9, 4, 4);
    sp(g, 10, 4, 3);
    sp(g, 7, 6, 4);
    sp(g, 8, 6, 4);
    sp(g, 6, 7, 3);
    sp(g, 7, 7, 3);
    sp(g, 8, 7, 3);
    sp(g, 9, 7, 3);
    sp(g, 1, 6, 3);
    sp(g, 2, 6, 3);
    sp(g, 13, 6, 3);
    sp(g, 14, 6, 3);
    sp(g, 1, 7, 3);
    sp(g, 2, 7, 3);
    sp(g, 13, 7, 3);
    sp(g, 14, 7, 3);
    fr(g, 3, 9, 10, 5, 0);
    fr(g, 5, 10, 6, 3, 7);
    if b[8] > 128 {
        sp(g, 3, 10, 3);
        sp(g, 12, 10, 3);
        sp(g, 3, 12, 3);
        sp(g, 12, 12, 3);
    }
    fr(g, 3, 13, 3, 3, 0);
    fr(g, 10, 13, 3, 3, 0);
    sp(g, 3, 15, 7);
    sp(g, 4, 15, 7);
    sp(g, 5, 15, 7);
    sp(g, 10, 15, 7);
    sp(g, 11, 15, 7);
    sp(g, 12, 15, 7);
    sp(g, 13, 11, 0);
    sp(g, 14, 12, 0);
    sp(g, 15, 13, 0);
    sp(g, 15, 14, 0);
    sp(g, 14, 15, 0);
}

fn gen_rabbit(b: &[u8; 32], g: &mut Grid) {
    let floppy = b[9] > 128;
    if !floppy {
        fr(g, 5, 0, 2, 6, 0);
        fr(g, 9, 0, 2, 6, 0);
        sp(g, 6, 1, 4);
        sp(g, 6, 2, 4);
        sp(g, 6, 3, 4);
        sp(g, 6, 4, 4);
        sp(g, 10, 1, 4);
        sp(g, 10, 2, 4);
        sp(g, 10, 3, 4);
        sp(g, 10, 4, 4);
    } else {
        fr(g, 1, 2, 5, 2, 0);
        fr(g, 10, 2, 5, 2, 0);
        sp(g, 2, 2, 4);
        sp(g, 3, 2, 4);
        sp(g, 11, 2, 4);
        sp(g, 12, 2, 4);
    }
    fr(g, 4, 4, 8, 6, 0);
    fr(g, 5, 5, 6, 4, 7);
    sp(g, 6, 6, 4);
    sp(g, 7, 6, 3);
    sp(g, 9, 6, 4);
    sp(g, 10, 6, 3);
    sp(g, 7, 8, 4);
    sp(g, 8, 8, 4);
    sp(g, 6, 9, 3);
    sp(g, 7, 9, 3);
    sp(g, 8, 9, 3);
    sp(g, 9, 9, 3);
    if b[10] > 150 {
        sp(g, 5, 8, 4);
        sp(g, 10, 8, 4);
    }
    fr(g, 3, 10, 10, 5, 0);
    fr(g, 5, 11, 6, 3, 7);
    if b[8] > 180 {
        sp(g, 4, 12, 3);
        sp(g, 8, 13, 3);
        sp(g, 11, 12, 3);
    }
    fr(g, 3, 14, 4, 2, 0);
    fr(g, 9, 14, 4, 2, 0);
    sp(g, 3, 15, 7);
    sp(g, 4, 15, 7);
    sp(g, 9, 15, 7);
    sp(g, 10, 15, 7);
    sp(g, 2, 12, 7);
    sp(g, 2, 13, 7);
}

fn gen_bear(b: &[u8; 32], g: &mut Grid) {
    let panda = b[8] > 200;
    fr(g, 3, 1, 3, 2, 0);
    fr(g, 10, 1, 3, 2, 0);
    sp(g, 4, 1, 7);
    sp(g, 11, 1, 7);
    fr(g, 2, 2, 12, 7, 0);
    fr(g, 4, 6, 8, 3, 7);
    if panda {
        fr(g, 4, 4, 3, 2, 3);
        fr(g, 9, 4, 3, 2, 3);
    }
    sp(g, 5, 4, 4);
    sp(g, 6, 4, 3);
    sp(g, 9, 4, 4);
    sp(g, 10, 4, 3);
    fr(g, 6, 6, 4, 2, 3);
    sp(g, 6, 8, 3);
    sp(g, 7, 8, 3);
    sp(g, 8, 8, 3);
    sp(g, 9, 8, 3);
    fr(g, 3, 9, 10, 6, 0);
    fr(g, 5, 10, 6, 4, 7);
    sp(g, 2, 10, 0);
    sp(g, 2, 11, 0);
    sp(g, 13, 10, 0);
    sp(g, 13, 11, 0);
    sp(g, 1, 11, 0);
    sp(g, 14, 11, 0);
    fr(g, 1, 12, 3, 2, 0);
    fr(g, 12, 12, 3, 2, 0);
    fr(g, 3, 14, 4, 2, 0);
    fr(g, 9, 14, 4, 2, 0);
    sp(g, 3, 15, 7);
    sp(g, 4, 15, 7);
    sp(g, 5, 15, 7);
    sp(g, 10, 15, 7);
    sp(g, 11, 15, 7);
    sp(g, 12, 15, 7);
}

fn gen_fox(_b: &[u8; 32], g: &mut Grid) {
    sp(g, 3, 0, 0);
    sp(g, 12, 0, 0);
    sp(g, 2, 1, 0);
    sp(g, 4, 1, 0);
    sp(g, 11, 1, 0);
    sp(g, 13, 1, 0);
    sp(g, 3, 1, 4);
    sp(g, 12, 1, 4);
    fr(g, 2, 2, 3, 1, 0);
    fr(g, 11, 2, 3, 1, 0);
    fr(g, 3, 2, 10, 7, 0);
    fr(g, 5, 3, 6, 3, 7);
    fr(g, 6, 5, 4, 3, 7);
    sp(g, 5, 4, 4);
    sp(g, 6, 4, 3);
    sp(g, 9, 4, 4);
    sp(g, 10, 4, 3);
    sp(g, 4, 4, 3);
    sp(g, 11, 4, 3);
    sp(g, 7, 6, 3);
    sp(g, 8, 6, 3);
    sp(g, 6, 7, 3);
    sp(g, 9, 7, 3);
    fr(g, 7, 7, 2, 1, 5);
    sp(g, 4, 6, 3);
    sp(g, 11, 6, 3);
    fr(g, 3, 9, 10, 6, 0);
    fr(g, 5, 9, 6, 5, 7);
    sp(g, 12, 10, 0);
    sp(g, 13, 11, 0);
    sp(g, 14, 11, 0);
    sp(g, 14, 12, 0);
    sp(g, 15, 12, 0);
    sp(g, 15, 13, 0);
    sp(g, 14, 14, 0);
    sp(g, 13, 15, 0);
    sp(g, 14, 15, 7);
    fr(g, 3, 14, 4, 2, 0);
    fr(g, 9, 14, 4, 2, 0);
}

fn gen_penguin(b: &[u8; 32], g: &mut Grid) {
    let bw = b[8] > 180;
    let hat = b[9] > 200;
    if hat {
        fr(g, 5, 0, 6, 3, 3);
        fr(g, 4, 3, 8, 1, 6);
    }
    fr(g, 4, 3, 8, 6, 3);
    fr(g, 5, 4, 6, 4, 5);
    sp(g, 5, 5, 4);
    sp(g, 6, 5, 3);
    sp(g, 9, 5, 4);
    sp(g, 10, 5, 3);
    fr(g, 7, 7, 2, 2, 4);
    fr(g, 3, 9, 10, 6, 3);
    fr(g, 5, 9, 6, 6, 5);
    sp(g, 2, 10, 3);
    sp(g, 2, 11, 3);
    sp(g, 2, 12, 3);
    sp(g, 2, 13, 3);
    sp(g, 13, 10, 3);
    sp(g, 13, 11, 3);
    sp(g, 13, 12, 3);
    sp(g, 13, 13, 3);
    if bw {
        fr(g, 6, 9, 2, 2, 4);
        fr(g, 8, 9, 2, 2, 4);
        sp(g, 8, 10, 4);
        sp(g, 7, 10, 4);
    }
    fr(g, 4, 15, 4, 1, 4);
    fr(g, 8, 15, 4, 1, 4);
    sp(g, 3, 15, 4);
    sp(g, 12, 15, 4);
}

fn gen_frog(b: &[u8; 32], g: &mut Grid) {
    let crown = b[8] > 200;
    let happy = b[9] > 128;
    fr(g, 3, 2, 3, 3, 0);
    fr(g, 10, 2, 3, 3, 0);
    sp(g, 4, 2, 4);
    sp(g, 5, 2, 3);
    sp(g, 10, 2, 4);
    sp(g, 11, 2, 3);
    if crown {
        sp(g, 7, 0, 4);
        sp(g, 8, 0, 4);
        sp(g, 6, 1, 4);
        sp(g, 9, 1, 4);
        fr(g, 6, 2, 4, 1, 4);
    }
    fr(g, 2, 4, 12, 5, 0);
    fr(g, 3, 5, 10, 3, 7);
    if happy {
        fr(g, 4, 8, 8, 1, 4);
    } else {
        fr(g, 5, 8, 6, 1, 3);
    }
    sp(g, 4, 7, 3);
    sp(g, 11, 7, 3);
    sp(g, 6, 6, 3);
    sp(g, 9, 6, 3);
    fr(g, 2, 9, 12, 5, 0);
    fr(g, 4, 10, 8, 3, 7);
    sp(g, 1, 9, 0);
    sp(g, 0, 10, 0);
    sp(g, 0, 11, 0);
    sp(g, 1, 12, 0);
    sp(g, 14, 9, 0);
    sp(g, 15, 10, 0);
    sp(g, 15, 11, 0);
    sp(g, 14, 12, 0);
    fr(g, 2, 14, 4, 2, 0);
    fr(g, 10, 14, 4, 2, 0);
    sp(g, 1, 15, 0);
    sp(g, 6, 15, 0);
    sp(g, 9, 15, 0);
    sp(g, 14, 15, 0);
}

fn gen_dog(b: &[u8; 32], g: &mut Grid) {
    let spotted = b[8] > 180;
    let tongue = b[9] > 200;
    let collar = b[10] > 150;
    fr(g, 2, 3, 2, 5, 0);
    fr(g, 12, 3, 2, 5, 0);
    sp(g, 2, 3, 7);
    sp(g, 3, 3, 7);
    sp(g, 12, 3, 7);
    sp(g, 13, 3, 7);
    sp(g, 2, 7, 7);
    sp(g, 3, 7, 7);
    sp(g, 12, 7, 7);
    sp(g, 13, 7, 7);
    fr(g, 4, 2, 8, 7, 0);
    fr(g, 5, 6, 6, 2, 7);
    sp(g, 5, 4, 4);
    sp(g, 6, 4, 3);
    sp(g, 9, 4, 4);
    sp(g, 10, 4, 3);
    fr(g, 6, 6, 4, 1, 3);
    sp(g, 5, 8, 3);
    sp(g, 6, 8, 3);
    sp(g, 7, 8, 3);
    sp(g, 8, 8, 3);
    sp(g, 9, 8, 3);
    sp(g, 10, 8, 3);
    if tongue {
        fr(g, 7, 8, 2, 2, 4);
    }
    if collar {
        fr(g, 4, 9, 8, 1, 4);
        sp(g, 7, 9, 5);
        sp(g, 8, 9, 5);
    }
    fr(g, 3, 9, 10, 6, 0);
    fr(g, 5, 10, 6, 4, 7);
    if spotted {
        sp(g, 4, 10, 3);
        sp(g, 9, 11, 3);
        sp(g, 7, 13, 3);
    }
    sp(g, 12, 10, 0);
    sp(g, 13, 9, 0);
    sp(g, 14, 8, 0);
    sp(g, 14, 7, 0);
    sp(g, 13, 7, 0);
    fr(g, 3, 14, 3, 2, 0);
    fr(g, 10, 14, 3, 2, 0);
    sp(g, 3, 15, 7);
    sp(g, 4, 15, 7);
    sp(g, 5, 15, 7);
    sp(g, 10, 15, 7);
    sp(g, 11, 15, 7);
    sp(g, 12, 15, 7);
}

fn gen_wolf(b: &[u8; 32], g: &mut Grid) {
    let howling = b[8] > 200;
    let scar = b[9] > 180;
    sp(g, 3, 0, 0);
    sp(g, 4, 0, 0);
    sp(g, 11, 0, 0);
    sp(g, 12, 0, 0);
    sp(g, 3, 1, 0);
    sp(g, 12, 1, 0);
    sp(g, 4, 1, 7);
    sp(g, 11, 1, 7);
    fr(g, 3, 2, 3, 1, 0);
    fr(g, 10, 2, 3, 1, 0);
    fr(g, 3, 2, 10, 7, 0);
    fr(g, 5, 6, 6, 3, 7);
    sp(g, 5, 4, 4);
    sp(g, 6, 4, 3);
    sp(g, 9, 4, 4);
    sp(g, 10, 4, 3);
    sp(g, 4, 3, 3);
    sp(g, 11, 3, 3);
    fr(g, 6, 6, 4, 2, 3);
    if !howling {
        sp(g, 5, 8, 3);
        sp(g, 10, 8, 3);
        fr(g, 6, 8, 4, 1, 5);
        sp(g, 6, 9, 5);
        sp(g, 9, 9, 5);
    } else {
        fr(g, 5, 7, 6, 3, 3);
        fr(g, 6, 8, 4, 1, 5);
        sp(g, 0, 3, 7);
        sp(g, 1, 2, 7);
        sp(g, 0, 5, 7);
        sp(g, 1, 6, 7);
    }
    if scar {
        sp(g, 7, 3, 7);
        sp(g, 7, 4, 7);
    }
    fr(g, 2, 9, 12, 6, 0);
    fr(g, 4, 10, 8, 4, 7);
    fr(g, 2, 14, 4, 2, 0);
    fr(g, 10, 14, 4, 2, 0);
    sp(g, 2, 15, 3);
    sp(g, 3, 15, 3);
    sp(g, 4, 15, 3);
    sp(g, 10, 15, 3);
    sp(g, 11, 15, 3);
    sp(g, 12, 15, 3);
    sp(g, 12, 11, 0);
    sp(g, 13, 10, 0);
    sp(g, 14, 9, 0);
    sp(g, 15, 8, 0);
    sp(g, 15, 9, 7);
    sp(g, 14, 10, 7);
}

fn gen_duck(b: &[u8; 32], g: &mut Grid) {
    let bow = b[8] > 180;
    let happy = b[9] > 128;
    fr(g, 4, 1, 8, 6, 0);
    fr(g, 5, 2, 6, 4, 7);
    sp(g, 6, 3, 3);
    sp(g, 7, 3, 5);
    sp(g, 9, 3, 3);
    sp(g, 10, 3, 5);
    fr(g, 9, 4, 4, 2, 4);
    sp(g, 3, 4, 4);
    sp(g, 3, 5, 4);
    fr(g, 9, 6, 3, 1, 3);
    if bow {
        sp(g, 6, 1, 4);
        sp(g, 5, 0, 4);
        sp(g, 7, 0, 4);
        sp(g, 8, 1, 4);
        sp(g, 6, 0, 5);
        sp(g, 7, 0, 5);
    }
    if happy {
        sp(g, 5, 6, 3);
        sp(g, 6, 7, 3);
        sp(g, 7, 7, 3);
        sp(g, 8, 7, 3);
        sp(g, 9, 6, 3);
    } else {
        fr(g, 5, 7, 6, 1, 3);
    }
    fr(g, 2, 7, 12, 7, 0);
    fr(g, 3, 8, 10, 5, 7);
    sp(g, 2, 9, 3);
    sp(g, 2, 10, 3);
    sp(g, 2, 11, 3);
    sp(g, 13, 9, 3);
    sp(g, 13, 10, 3);
    sp(g, 13, 11, 3);
    fr(g, 4, 14, 4, 2, 4);
    fr(g, 8, 14, 4, 2, 4);
    sp(g, 3, 15, 4);
    sp(g, 8, 15, 4);
    sp(g, 12, 15, 4);
}

fn gen_panda(b: &[u8; 32], g: &mut Grid) {
    let with_bamboo = b[8] > 200;
    fr(g, 3, 1, 3, 2, 3);
    fr(g, 10, 1, 3, 2, 3);
    fr(g, 2, 2, 12, 7, 5);
    fr(g, 4, 3, 8, 5, 7);
    fr(g, 3, 3, 4, 3, 3);
    fr(g, 9, 3, 4, 3, 3);
    sp(g, 5, 4, 5);
    sp(g, 6, 4, 3);
    sp(g, 9, 4, 5);
    sp(g, 10, 4, 3);
    fr(g, 6, 7, 2, 1, 3);
    fr(g, 7, 8, 2, 1, 3);
    sp(g, 6, 9, 3);
    sp(g, 7, 9, 3);
    sp(g, 8, 9, 3);
    sp(g, 9, 9, 3);
    fr(g, 2, 9, 12, 6, 5);
    fr(g, 2, 10, 2, 4, 3);
    fr(g, 12, 10, 2, 4, 3);
    fr(g, 3, 14, 4, 2, 3);
    fr(g, 9, 14, 4, 2, 3);
    sp(g, 3, 15, 7);
    sp(g, 4, 15, 7);
    sp(g, 9, 15, 7);
    sp(g, 10, 15, 7);
    if with_bamboo {
        fr(g, 0, 5, 2, 10, 0);
        sp(g, 0, 7, 3);
        sp(g, 0, 9, 3);
        sp(g, 0, 11, 3);
        sp(g, 0, 13, 3);
        sp(g, 2, 11, 3);
        sp(g, 3, 12, 3);
    }
}

// ── Plants ──────────────────────────────────────────────────────────────
fn gen_plant(b: &[u8; 32], g: &mut Grid) {
    match b[7] % 7 {
        0 => gen_flower(b, g),
        1 => gen_tree(b, g),
        2 => gen_mushroom(b, g),
        3 => gen_cactus(b, g),
        4 => gen_crystal(b, g),
        5 => gen_sunflower(b, g),
        _ => gen_bamboo(b, g),
    }
}

fn gen_flower(b: &[u8; 32], g: &mut Grid) {
    let pet_n = 4 + (b[8] % 4) as i32;
    let long_p = b[9] > 128;
    fr(g, 4, 13, 8, 1, 6);
    fr(g, 5, 14, 6, 2, 6);
    fr(g, 5, 13, 6, 1, 3);
    fr(g, 7, 7, 2, 6, 0);
    if b[10] > 100 {
        fr(g, 3, 9, 4, 2, 0);
        sp(g, 5, 10, 7);
    }
    if b[10] > 50 {
        fr(g, 9, 10, 4, 2, 0);
        sp(g, 10, 11, 7);
    }
    let dirs: [[i32; 2]; 12] = [
        [0, -2],
        [1, -2],
        [2, -1],
        [2, 0],
        [2, 1],
        [1, 2],
        [0, 2],
        [-1, 2],
        [-2, 1],
        [-2, 0],
        [-2, -1],
        [-1, -2],
    ];
    for i in 0..pet_n * 2 {
        let d = dirs[(i % 12) as usize];
        let dc = d[0];
        let dr = d[1];
        fr(g, 7 + dc, 4 + dr, 2, 1, 1);
        if long_p {
            sp(g, 7 + dc * 2, 4 + dr * 2, 1);
        }
    }
    fr(g, 6, 3, 4, 4, 4);
    sp(g, 7, 4, 5);
    sp(g, 8, 4, 5);
}

fn gen_tree(b: &[u8; 32], g: &mut Grid) {
    let has_apple = b[9] > 200;
    let has_bird = b[10] > 220;
    fr(g, 6, 11, 4, 5, 6);
    fr(g, 7, 10, 2, 2, 3);
    fr(g, 2, 9, 12, 3, 0);
    sp(g, 1, 10, 0);
    sp(g, 14, 10, 0);
    fr(g, 4, 6, 8, 4, 0);
    fr(g, 5, 3, 6, 4, 0);
    sp(g, 6, 1, 0);
    sp(g, 7, 1, 0);
    sp(g, 8, 1, 0);
    sp(g, 9, 1, 0);
    sp(g, 5, 4, 7);
    sp(g, 6, 4, 7);
    sp(g, 5, 7, 7);
    if has_apple {
        sp(g, 10, 7, 4);
        sp(g, 11, 7, 4);
        sp(g, 10, 8, 4);
        sp(g, 9, 8, 4);
    }
    if has_bird {
        sp(g, 7, 0, 3);
        sp(g, 8, 0, 3);
        sp(g, 9, 0, 1);
        sp(g, 7, 1, 3);
        sp(g, 6, 1, 3);
    }
    fr(g, 0, 15, 16, 1, 0);
    sp(g, 0, 14, 0);
    sp(g, 15, 14, 0);
}

fn gen_mushroom(b: &[u8; 32], g: &mut Grid) {
    let big_spots = b[8] > 128;
    let face = b[10] > 150;
    fr(g, 5, 9, 6, 6, 7);
    sp(g, 4, 9, 8);
    sp(g, 11, 9, 8);
    fr(g, 6, 10, 4, 1, 3);
    fr(g, 2, 4, 12, 6, 1);
    fr(g, 3, 2, 10, 3, 1);
    fr(g, 5, 0, 6, 2, 1);
    sp(g, 6, 0, 1);
    sp(g, 9, 0, 1);
    fr(g, 5, 9, 6, 1, 8);
    sp(g, 4, 9, 8);
    sp(g, 11, 9, 8);
    if big_spots {
        fr(g, 4, 5, 3, 2, 5);
        fr(g, 9, 4, 3, 3, 5);
        fr(g, 6, 2, 2, 2, 5);
    } else {
        sp(g, 5, 5, 5);
        sp(g, 9, 6, 5);
        sp(g, 7, 3, 5);
        sp(g, 11, 4, 5);
        sp(g, 4, 7, 5);
    }
    if face {
        sp(g, 6, 7, 3);
        sp(g, 7, 7, 3);
        sp(g, 9, 7, 3);
        sp(g, 10, 7, 3);
        sp(g, 7, 8, 3);
        sp(g, 8, 8, 3);
        sp(g, 9, 8, 3);
    }
    fr(g, 0, 15, 16, 1, 0);
}

fn gen_cactus(b: &[u8; 32], g: &mut Grid) {
    let arms = 1 + (b[8] % 3);
    let flower = b[9] > 200;
    fr(g, 4, 12, 8, 4, 6);
    fr(g, 5, 11, 6, 1, 3);
    fr(g, 6, 2, 4, 10, 0);
    if arms >= 1 {
        fr(g, 3, 5, 3, 1, 0);
        fr(g, 3, 4, 1, 2, 0);
        fr(g, 2, 4, 4, 3, 0);
    }
    if arms >= 2 {
        fr(g, 10, 7, 3, 1, 0);
        fr(g, 12, 6, 1, 2, 0);
    }
    if arms >= 3 {
        fr(g, 2, 8, 4, 1, 0);
        sp(g, 2, 7, 0);
        sp(g, 2, 9, 0);
    }
    sp(g, 5, 3, 7);
    sp(g, 10, 3, 7);
    sp(g, 5, 6, 7);
    sp(g, 10, 8, 7);
    sp(g, 5, 10, 7);
    sp(g, 10, 10, 7);
    fr(g, 7, 4, 2, 7, 7);
    if flower {
        sp(g, 6, 1, 4);
        sp(g, 9, 1, 4);
        sp(g, 7, 0, 4);
        sp(g, 8, 0, 4);
        sp(g, 7, 1, 1);
        sp(g, 8, 1, 1);
    }
}

fn gen_crystal(b: &[u8; 32], g: &mut Grid) {
    let glow = b[9] > 150;
    let sides = b[8] % 3;
    sp(g, 7, 0, 4);
    sp(g, 8, 0, 4);
    fr(g, 6, 1, 4, 1, 4);
    fr(g, 5, 2, 6, 1, 4);
    fr(g, 4, 3, 8, 1, 4);
    fr(g, 4, 4, 8, 4, 1);
    fr(g, 4, 8, 8, 4, 0);
    fr(g, 5, 12, 6, 1, 8);
    fr(g, 6, 13, 4, 2, 8);
    sp(g, 7, 15, 5);
    sp(g, 8, 15, 5);
    fr(g, 6, 4, 4, 4, 7);
    sp(g, 6, 3, 5);
    sp(g, 9, 3, 5);
    if sides >= 1 {
        sp(g, 3, 4, 4);
        sp(g, 2, 5, 4);
        sp(g, 3, 5, 4);
        fr(g, 2, 6, 2, 4, 1);
        sp(g, 3, 10, 1);
        sp(g, 12, 5, 4);
        sp(g, 13, 6, 4);
        fr(g, 12, 7, 2, 3, 1);
    }
    if sides >= 2 {
        sp(g, 1, 7, 4);
        fr(g, 1, 8, 1, 3, 1);
    }
    if glow {
        sp(g, 1, 2, 5);
        sp(g, 14, 3, 5);
        sp(g, 0, 10, 5);
        sp(g, 15, 8, 5);
        sp(g, 2, 14, 5);
        sp(g, 13, 13, 5);
    }
}

fn gen_sunflower(b: &[u8; 32], g: &mut Grid) {
    let face = b[8] > 150;
    fr(g, 4, 13, 8, 1, 6);
    fr(g, 5, 14, 6, 2, 6);
    fr(g, 5, 13, 6, 1, 3);
    fr(g, 7, 7, 2, 6, 0);
    fr(g, 3, 9, 4, 2, 0);
    sp(g, 6, 10, 7);
    fr(g, 9, 10, 4, 2, 0);
    sp(g, 10, 11, 7);
    fr(g, 5, 0, 6, 2, 4);
    fr(g, 5, 8, 6, 2, 4);
    fr(g, 2, 2, 3, 6, 4);
    fr(g, 11, 2, 3, 6, 4);
    fr(g, 4, 1, 3, 2, 4);
    fr(g, 9, 1, 3, 2, 4);
    fr(g, 4, 7, 3, 2, 4);
    fr(g, 9, 7, 3, 2, 4);
    fr(g, 4, 2, 8, 6, 6);
    fr(g, 5, 3, 6, 4, 3);
    if face {
        sp(g, 6, 4, 5);
        sp(g, 7, 4, 3);
        sp(g, 8, 4, 5);
        sp(g, 9, 4, 3);
        sp(g, 6, 6, 3);
        sp(g, 7, 7, 3);
        sp(g, 8, 7, 3);
        sp(g, 9, 6, 3);
    } else {
        sp(g, 6, 3, 3);
        sp(g, 8, 3, 3);
        sp(g, 7, 4, 3);
        sp(g, 9, 4, 3);
        sp(g, 6, 5, 3);
        sp(g, 8, 5, 3);
        sp(g, 7, 6, 3);
    }
}

fn gen_bamboo(b: &[u8; 32], g: &mut Grid) {
    let double = b[8] > 150;
    let lantern = b[9] > 200;
    fr(g, 0, 14, 16, 2, 0);
    fr(g, 0, 15, 16, 1, 6);
    fr(g, 5, 0, 2, 14, 0);
    fr(g, 6, 0, 1, 14, 7);
    fr(g, 4, 3, 4, 1, 3);
    fr(g, 4, 7, 4, 1, 3);
    fr(g, 4, 11, 4, 1, 3);
    sp(g, 5, 4, 7);
    sp(g, 6, 4, 7);
    sp(g, 5, 8, 7);
    sp(g, 6, 8, 7);
    sp(g, 3, 2, 0);
    sp(g, 2, 1, 0);
    sp(g, 1, 0, 0);
    sp(g, 4, 1, 7);
    fr(g, 8, 3, 4, 2, 0);
    sp(g, 9, 5, 7);
    fr(g, 2, 7, 4, 2, 0);
    sp(g, 4, 9, 7);
    fr(g, 9, 8, 4, 2, 0);
    sp(g, 10, 10, 7);
    fr(g, 2, 11, 3, 2, 0);
    sp(g, 4, 13, 7);
    if double {
        fr(g, 10, 2, 2, 12, 0);
        fr(g, 11, 2, 1, 12, 7);
        fr(g, 9, 5, 4, 1, 3);
        fr(g, 9, 9, 4, 1, 3);
        fr(g, 9, 13, 4, 1, 3);
        fr(g, 12, 4, 3, 2, 0);
        sp(g, 13, 6, 7);
    }
    if lantern {
        sp(g, 7, 0, 4);
        sp(g, 8, 0, 4);
        fr(g, 6, 1, 4, 3, 4);
        sp(g, 7, 4, 3);
        sp(g, 8, 4, 3);
    }
}

// ── Monsters ────────────────────────────────────────────────────────────
fn gen_monster(b: &[u8; 32], g: &mut Grid) {
    match b[7] % 7 {
        0 => gen_slime(b, g),
        1 => gen_ghost(b, g),
        2 => gen_demon(b, g),
        3 => gen_alien(b, g),
        4 => gen_eyeball(b, g),
        5 => gen_skull(b, g),
        _ => gen_spider(b, g),
    }
}

fn gen_slime(b: &[u8; 32], g: &mut Grid) {
    let drip = b[8] % 3;
    let angry = b[9] > 200;
    if drip == 0 {
        fr(g, 6, 0, 4, 2, 0);
        sp(g, 5, 1, 0);
        sp(g, 10, 1, 0);
    } else if drip == 1 {
        sp(g, 7, 0, 0);
        sp(g, 8, 0, 0);
        fr(g, 6, 1, 4, 1, 0);
        sp(g, 5, 2, 0);
        sp(g, 10, 2, 0);
    } else {
        fr(g, 5, 0, 6, 2, 0);
        sp(g, 4, 1, 0);
        sp(g, 11, 1, 0);
        sp(g, 4, 2, 0);
        sp(g, 11, 2, 0);
    }
    fr(g, 3, 3, 10, 8, 0);
    fr(g, 2, 5, 12, 5, 0);
    fr(g, 3, 10, 10, 3, 0);
    sp(g, 4, 13, 0);
    sp(g, 11, 13, 0);
    fr(g, 5, 13, 6, 1, 0);
    sp(g, 6, 14, 0);
    sp(g, 9, 14, 0);
    fr(g, 7, 14, 2, 1, 0);
    sp(g, 7, 15, 0);
    sp(g, 8, 15, 0);
    fr(g, 5, 4, 4, 3, 7);
    if angry {
        fr(g, 5, 6, 2, 2, 3);
        fr(g, 9, 6, 2, 2, 3);
        sp(g, 5, 5, 3);
        sp(g, 6, 5, 3);
        sp(g, 9, 5, 3);
        sp(g, 10, 5, 3);
    } else {
        sp(g, 5, 6, 5);
        sp(g, 6, 6, 3);
        sp(g, 9, 6, 5);
        sp(g, 10, 6, 3);
    }
    fr(g, 6, 9, 4, 1, 3);
    sp(g, 5, 9, 3);
    sp(g, 10, 9, 3);
    if b[10] > 150 {
        sp(g, 2, 4, 7);
        sp(g, 13, 6, 7);
        sp(g, 1, 8, 7);
    }
}

fn gen_ghost(b: &[u8; 32], g: &mut Grid) {
    let smile = b[8] > 128;
    let wavy_t = b[9] % 3;
    fr(g, 3, 1, 10, 4, 5);
    fr(g, 2, 4, 12, 8, 5);
    for r in 5..=8i32 {
        sp(g, 1, r, 5);
        sp(g, 14, r, 5);
    }
    if wavy_t == 0 {
        fr(g, 2, 12, 3, 3, 5);
        fr(g, 7, 12, 4, 3, 5);
        fr(g, 13, 12, 1, 3, 5);
    } else if wavy_t == 1 {
        fr(g, 2, 12, 12, 2, 5);
        sp(g, 4, 14, 5);
        sp(g, 7, 14, 5);
        sp(g, 10, 14, 5);
        sp(g, 13, 14, 5);
    } else {
        fr(g, 3, 12, 10, 2, 5);
        sp(g, 3, 14, 5);
        sp(g, 5, 14, 5);
        sp(g, 8, 14, 5);
        sp(g, 11, 14, 5);
        sp(g, 13, 14, 5);
    }
    fr(g, 4, 5, 3, 3, 3);
    fr(g, 9, 5, 3, 3, 3);
    sp(g, 5, 6, 4);
    sp(g, 10, 6, 4);
    if smile {
        sp(g, 5, 9, 3);
        sp(g, 7, 10, 3);
        sp(g, 8, 10, 3);
        sp(g, 10, 9, 3);
        fr(g, 6, 9, 4, 1, 3);
    } else {
        fr(g, 5, 9, 6, 2, 3);
    }
    sp(g, 2, 3, 8);
    sp(g, 13, 3, 8);
    sp(g, 1, 4, 8);
    sp(g, 14, 4, 8);
}

fn gen_demon(b: &[u8; 32], g: &mut Grid) {
    let wings = b[8] > 128;
    let fangs = b[9] > 150;
    sp(g, 4, 0, 0);
    sp(g, 3, 1, 0);
    sp(g, 4, 1, 0);
    sp(g, 4, 2, 0);
    sp(g, 11, 0, 0);
    sp(g, 12, 1, 0);
    sp(g, 11, 1, 0);
    sp(g, 11, 2, 0);
    fr(g, 3, 2, 10, 8, 0);
    sp(g, 4, 4, 4);
    sp(g, 5, 4, 4);
    sp(g, 6, 4, 3);
    sp(g, 9, 4, 4);
    sp(g, 10, 4, 4);
    sp(g, 11, 4, 3);
    sp(g, 4, 3, 3);
    sp(g, 5, 3, 3);
    sp(g, 10, 3, 3);
    sp(g, 11, 3, 3);
    sp(g, 7, 6, 3);
    sp(g, 8, 6, 3);
    fr(g, 5, 7, 6, 2, 3);
    if fangs {
        sp(g, 6, 9, 5);
        sp(g, 7, 9, 5);
        sp(g, 9, 9, 5);
        sp(g, 10, 9, 5);
    }
    if wings {
        sp(g, 1, 5, 0);
        sp(g, 0, 6, 0);
        sp(g, 0, 7, 0);
        sp(g, 1, 8, 0);
        sp(g, 1, 9, 0);
        sp(g, 0, 10, 0);
        sp(g, 14, 5, 0);
        sp(g, 15, 6, 0);
        sp(g, 15, 7, 0);
        sp(g, 14, 8, 0);
        sp(g, 14, 9, 0);
        sp(g, 15, 10, 0);
        sp(g, 1, 6, 8);
        sp(g, 1, 7, 8);
        sp(g, 14, 6, 8);
        sp(g, 14, 7, 8);
    }
    fr(g, 4, 10, 8, 5, 0);
    fr(g, 6, 11, 4, 3, 1);
    sp(g, 11, 13, 0);
    sp(g, 12, 14, 0);
    sp(g, 13, 15, 0);
    sp(g, 14, 14, 0);
    sp(g, 15, 13, 0);
    sp(g, 14, 15, 3);
    sp(g, 15, 14, 3);
}

fn gen_alien(b: &[u8; 32], g: &mut Grid) {
    let ant_n = b[8] % 3;
    let spots = b[9] > 180;
    if ant_n == 0 {
        sp(g, 6, 0, 0);
        sp(g, 9, 0, 0);
        sp(g, 6, 1, 0);
        sp(g, 9, 1, 0);
        sp(g, 6, 2, 7);
        sp(g, 9, 2, 7);
    } else if ant_n == 1 {
        sp(g, 7, 0, 4);
        sp(g, 8, 0, 4);
        fr(g, 7, 1, 2, 2, 0);
    } else {
        sp(g, 5, 0, 0);
        sp(g, 10, 0, 0);
        fr(g, 6, 0, 4, 1, 0);
    }
    fr(g, 3, 2, 10, 7, 0);
    fr(g, 2, 3, 12, 5, 0);
    fr(g, 3, 4, 4, 4, 4);
    fr(g, 9, 4, 4, 4, 4);
    fr(g, 4, 5, 2, 2, 3);
    fr(g, 10, 5, 2, 2, 3);
    sp(g, 4, 4, 5);
    sp(g, 10, 4, 5);
    fr(g, 6, 8, 4, 1, 3);
    fr(g, 6, 9, 4, 5, 0);
    sp(g, 5, 9, 8);
    sp(g, 5, 10, 8);
    sp(g, 5, 11, 8);
    sp(g, 10, 9, 8);
    sp(g, 10, 10, 8);
    sp(g, 10, 11, 8);
    if spots {
        sp(g, 7, 10, 4);
        sp(g, 8, 12, 4);
        sp(g, 6, 12, 7);
    }
    sp(g, 6, 14, 0);
    sp(g, 9, 14, 0);
    sp(g, 6, 15, 0);
    sp(g, 9, 15, 0);
    sp(g, 3, 10, 0);
    sp(g, 2, 11, 0);
    sp(g, 1, 12, 0);
    sp(g, 12, 10, 0);
    sp(g, 13, 11, 0);
    sp(g, 14, 12, 0);
}

fn gen_eyeball(b: &[u8; 32], g: &mut Grid) {
    let dilated = b[9] > 150;
    let lashes = b[10] > 128;
    fr(g, 2, 2, 12, 12, 5);
    fr(g, 1, 4, 14, 8, 5);
    sp(g, 3, 3, 5);
    sp(g, 12, 3, 5);
    sp(g, 3, 12, 5);
    sp(g, 12, 12, 5);
    fr(g, 4, 4, 8, 8, 4);
    fr(g, 5, 3, 6, 1, 4);
    fr(g, 5, 12, 6, 1, 4);
    fr(g, 3, 5, 1, 6, 4);
    fr(g, 12, 5, 1, 6, 4);
    let pr: i32 = if dilated { 3 } else { 2 };
    fr(g, 8 - pr, 8 - pr, pr * 2, pr * 2, 3);
    sp(g, 6, 6, 5);
    sp(g, 7, 6, 5);
    sp(g, 2, 5, 8);
    sp(g, 3, 4, 8);
    sp(g, 13, 7, 8);
    sp(g, 14, 9, 8);
    sp(g, 2, 10, 8);
    sp(g, 13, 5, 8);
    if lashes {
        sp(g, 4, 1, 3);
        sp(g, 6, 0, 3);
        sp(g, 8, 0, 3);
        sp(g, 10, 0, 3);
        sp(g, 12, 1, 3);
        sp(g, 4, 14, 3);
        sp(g, 6, 15, 3);
        sp(g, 8, 15, 3);
        sp(g, 10, 15, 3);
        sp(g, 12, 14, 3);
    }
}

fn gen_skull(b: &[u8; 32], g: &mut Grid) {
    let cracks = b[8] > 150;
    let pirate = b[9] > 180;
    let flowers = b[10] > 210;
    fr(g, 3, 2, 10, 8, 5);
    fr(g, 5, 1, 6, 2, 5);
    fr(g, 2, 4, 12, 4, 5);
    sp(g, 4, 2, 5);
    sp(g, 11, 2, 5);
    fr(g, 4, 4, 3, 3, 3);
    fr(g, 9, 4, 3, 3, 3);
    fr(g, 6, 7, 2, 2, 3);
    fr(g, 4, 9, 8, 3, 5);
    for t in 0..4i32 {
        sp(g, 4 + t * 2, 9, 5);
        sp(g, 4 + t * 2, 10, 5);
    }
    sp(g, 4, 8, 3);
    sp(g, 11, 8, 3);
    if cracks {
        sp(g, 7, 2, 3);
        sp(g, 7, 3, 3);
        sp(g, 8, 3, 3);
        sp(g, 9, 4, 3);
    }
    if pirate {
        fr(g, 3, 0, 10, 2, 3);
        fr(g, 2, 1, 12, 1, 3);
        sp(g, 7, 0, 5);
        sp(g, 8, 0, 5);
    }
    if flowers {
        sp(g, 1, 3, 4);
        sp(g, 1, 4, 4);
        sp(g, 14, 3, 4);
        sp(g, 14, 4, 4);
        sp(g, 2, 1, 4);
        sp(g, 13, 1, 4);
    }
    fr(g, 6, 12, 4, 1, 3);
}

fn gen_spider(b: &[u8; 32], g: &mut Grid) {
    let web = b[8] > 128;
    let hourglass = b[9] > 200;
    fr(g, 7, 0, 2, 3, 7);
    fr(g, 5, 3, 6, 5, 0);
    fr(g, 4, 8, 8, 6, 0);
    sp(g, 5, 4, 5);
    sp(g, 6, 4, 3);
    sp(g, 7, 4, 5);
    sp(g, 8, 4, 3);
    sp(g, 9, 4, 5);
    sp(g, 10, 4, 3);
    sp(g, 6, 8, 3);
    sp(g, 9, 8, 3);
    sp(g, 6, 9, 5);
    sp(g, 9, 9, 5);
    if hourglass {
        fr(g, 6, 9, 4, 2, 4);
        fr(g, 7, 11, 2, 2, 4);
    } else {
        sp(g, 7, 9, 4);
        sp(g, 8, 9, 4);
        sp(g, 7, 12, 4);
        sp(g, 8, 12, 4);
    }
    sp(g, 4, 4, 3);
    sp(g, 3, 3, 3);
    sp(g, 2, 2, 3);
    sp(g, 4, 5, 3);
    sp(g, 3, 5, 3);
    sp(g, 2, 6, 3);
    sp(g, 4, 6, 3);
    sp(g, 3, 7, 3);
    sp(g, 2, 8, 3);
    sp(g, 4, 7, 3);
    sp(g, 3, 8, 3);
    sp(g, 2, 9, 3);
    sp(g, 11, 4, 3);
    sp(g, 12, 3, 3);
    sp(g, 13, 2, 3);
    sp(g, 11, 5, 3);
    sp(g, 12, 5, 3);
    sp(g, 13, 6, 3);
    sp(g, 11, 6, 3);
    sp(g, 12, 7, 3);
    sp(g, 13, 8, 3);
    sp(g, 11, 7, 3);
    sp(g, 12, 8, 3);
    sp(g, 13, 9, 3);
    if web {
        sp(g, 0, 0, 7);
        sp(g, 1, 0, 7);
        sp(g, 0, 1, 7);
        sp(g, 15, 0, 7);
        sp(g, 14, 0, 7);
        sp(g, 15, 1, 7);
    }
}

// ── Robots ──────────────────────────────────────────────────────────────
fn gen_robot(b: &[u8; 32], g: &mut Grid) {
    match b[7] % 5 {
        0 => gen_retro_bot(b, g),
        1 => gen_android(b, g),
        2 => gen_mech(b, g),
        3 => gen_chibi_bot(b, g),
        _ => gen_tank_bot(b, g),
    }
}

fn gen_retro_bot(b: &[u8; 32], g: &mut Grid) {
    let happy = b[9] > 128;
    let led_v = b[8] % 3;
    sp(g, 7, 0, 4);
    sp(g, 8, 0, 4);
    fr(g, 7, 1, 2, 2, 8);
    fr(g, 2, 3, 12, 6, 8);
    fr(g, 3, 4, 10, 4, 6);
    fr(g, 3, 4, 3, 3, 3);
    fr(g, 10, 4, 3, 3, 3);
    sp(g, 4, 5, 4);
    sp(g, 5, 5, 4);
    sp(g, 11, 5, 4);
    sp(g, 12, 5, 4);
    if led_v == 2 {
        sp(g, 4, 4, 4);
        sp(g, 11, 4, 4);
    }
    if happy {
        sp(g, 5, 7, 4);
        sp(g, 6, 8, 4);
        sp(g, 7, 8, 4);
        sp(g, 8, 8, 4);
        sp(g, 9, 7, 4);
    } else {
        fr(g, 5, 7, 6, 1, 4);
    }
    fr(g, 7, 9, 2, 1, 8);
    fr(g, 2, 10, 12, 5, 8);
    fr(g, 3, 11, 10, 3, 6);
    sp(g, 5, 11, 4);
    sp(g, 8, 11, 4);
    sp(g, 11, 11, 4);
    fr(g, 5, 12, 6, 1, 3);
    fr(g, 0, 10, 2, 5, 8);
    fr(g, 14, 10, 2, 5, 8);
    sp(g, 0, 14, 6);
    sp(g, 1, 14, 6);
    sp(g, 14, 14, 6);
    sp(g, 15, 14, 6);
    fr(g, 3, 15, 4, 1, 6);
    fr(g, 9, 15, 4, 1, 6);
    sp(g, 3, 14, 8);
    sp(g, 4, 14, 8);
    sp(g, 5, 14, 8);
    sp(g, 9, 14, 8);
    sp(g, 10, 14, 8);
    sp(g, 11, 14, 8);
}

fn gen_android(b: &[u8; 32], g: &mut Grid) {
    let visor = b[8] > 128;
    fr(g, 4, 1, 8, 8, 8);
    fr(g, 3, 2, 10, 6, 8);
    if visor {
        fr(g, 4, 3, 8, 4, 3);
        fr(g, 5, 4, 6, 2, 4);
    } else {
        sp(g, 5, 4, 5);
        sp(g, 6, 4, 3);
        sp(g, 9, 4, 5);
        sp(g, 10, 4, 3);
        sp(g, 7, 6, 4);
        sp(g, 8, 6, 4);
    }
    fr(g, 7, 9, 2, 1, 6);
    fr(g, 3, 10, 10, 5, 8);
    fr(g, 4, 11, 8, 3, 6);
    sp(g, 7, 11, 4);
    sp(g, 8, 11, 4);
    fr(g, 1, 10, 2, 5, 8);
    fr(g, 13, 10, 2, 5, 8);
    fr(g, 0, 14, 2, 2, 6);
    fr(g, 14, 14, 2, 2, 6);
    fr(g, 4, 15, 3, 1, 6);
    fr(g, 9, 15, 3, 1, 6);
}

fn gen_mech(b: &[u8; 32], g: &mut Grid) {
    let cannon = b[8] > 180;
    fr(g, 4, 0, 8, 4, 8);
    sp(g, 3, 1, 6);
    sp(g, 12, 1, 6);
    fr(g, 4, 2, 8, 1, 3);
    sp(g, 5, 2, 4);
    sp(g, 6, 2, 4);
    sp(g, 9, 2, 4);
    sp(g, 10, 2, 4);
    fr(g, 5, 4, 6, 2, 6);
    fr(g, 1, 6, 14, 8, 8);
    fr(g, 2, 7, 12, 6, 6);
    sp(g, 7, 7, 3);
    fr(g, 7, 8, 2, 4, 3);
    fr(g, 0, 6, 2, 4, 6);
    fr(g, 14, 6, 2, 4, 6);
    fr(g, 0, 10, 3, 5, 8);
    fr(g, 13, 10, 3, 5, 8);
    if cannon {
        fr(g, 14, 12, 2, 2, 3);
        fr(g, 15, 11, 1, 4, 4);
    }
    fr(g, 2, 14, 4, 2, 8);
    fr(g, 10, 14, 4, 2, 8);
}

fn gen_chibi_bot(b: &[u8; 32], g: &mut Grid) {
    let happy = b[8] > 128;
    let ant_style = b[9] % 3;
    match ant_style {
        0 => {
            sp(g, 7, 0, 4);
            sp(g, 8, 0, 4);
            fr(g, 7, 1, 2, 2, 8);
        }
        1 => {
            sp(g, 6, 0, 4);
            sp(g, 8, 0, 5);
            sp(g, 10, 0, 4);
            fr(g, 7, 1, 2, 2, 8);
        }
        _ => {
            fr(g, 6, 0, 4, 1, 4);
            fr(g, 7, 1, 2, 2, 8);
        }
    }
    fr(g, 2, 2, 12, 7, 8);
    fr(g, 3, 3, 10, 5, 6);
    fr(g, 3, 3, 4, 4, 3);
    fr(g, 9, 3, 4, 4, 3);
    sp(g, 4, 4, 4);
    sp(g, 5, 4, 4);
    sp(g, 10, 4, 4);
    sp(g, 11, 4, 4);
    sp(g, 4, 3, 5);
    sp(g, 10, 3, 5);
    if happy {
        sp(g, 5, 7, 4);
        sp(g, 6, 8, 4);
        sp(g, 7, 8, 4);
        sp(g, 8, 8, 4);
        sp(g, 9, 7, 4);
    } else {
        fr(g, 5, 7, 6, 1, 4);
    }
    fr(g, 4, 9, 8, 5, 8);
    fr(g, 5, 10, 6, 3, 6);
    sp(g, 7, 10, 4);
    sp(g, 8, 10, 4);
    fr(g, 2, 13, 12, 3, 6);
    fr(g, 2, 13, 1, 3, 8);
    fr(g, 13, 13, 1, 3, 8);
    let mut t = 3;
    while t < 13 {
        sp(g, t, 14, 4);
        t += 2;
    }
}

fn gen_tank_bot(b: &[u8; 32], g: &mut Grid) {
    let left_facing = b[8] > 128;
    let double_cannon = b[9] > 200;
    fr(g, 4, 2, 8, 5, 8);
    fr(g, 5, 3, 6, 3, 6);
    fr(g, 5, 3, 6, 1, 3);
    sp(g, 6, 3, 4);
    sp(g, 7, 3, 4);
    sp(g, 8, 3, 4);
    sp(g, 9, 3, 4);
    if !left_facing {
        fr(g, 11, 4, 5, 2, 8);
        if double_cannon {
            fr(g, 11, 3, 4, 1, 8);
            fr(g, 11, 6, 4, 1, 8);
        }
    } else {
        fr(g, 0, 4, 5, 2, 8);
        if double_cannon {
            fr(g, 1, 3, 4, 1, 8);
            fr(g, 1, 6, 4, 1, 8);
        }
    }
    sp(g, 7, 1, 8);
    sp(g, 7, 0, 4);
    fr(g, 1, 6, 14, 6, 8);
    fr(g, 2, 7, 12, 4, 6);
    sp(g, 2, 6, 4);
    sp(g, 13, 6, 4);
    fr(g, 0, 11, 16, 5, 6);
    fr(g, 1, 11, 14, 1, 8);
    let mut t = 1;
    while t < 15 {
        sp(g, t, 13, 4);
        t += 2;
    }
    fr(g, 0, 11, 2, 5, 8);
    fr(g, 14, 11, 2, 5, 8);
    fr(g, 0, 15, 16, 1, 3);
}

// ── Bit-driven texture overlay ──────────────────────────────────────────
struct BitReader<'a> {
    b: &'a [u8; 32],
    i: usize,
}

impl<'a> BitReader<'a> {
    fn new(b: &'a [u8; 32], start_byte: usize) -> Self {
        Self { b, i: start_byte * 8 }
    }
    fn read(&mut self) -> u8 {
        if self.i >= 256 {
            return 0;
        }
        let byte = self.b[self.i >> 3];
        let bit = (byte >> (7 - (self.i & 7))) & 1;
        self.i += 1;
        bit
    }
}

/// For each zone `[c0, r0, c1, r1, p]`: walk a checkerboard pattern; if
/// the current bit is 1 AND the cell is empty, paint it palette index `p`.
fn tzones(br: &mut BitReader, g: &mut Grid, zones: &[[i32; 5]]) {
    for z in zones {
        let c0 = z[0];
        let r0 = z[1];
        let c1 = z[2];
        let r1 = z[3];
        let p = z[4] as u8;
        let mut r = r0;
        while r <= r1 {
            let mut c = c0 + ((r ^ c0) & 1);
            while c <= c1 {
                if br.read() != 0
                    && (0..GS as i32).contains(&r)
                    && (0..GS as i32).contains(&c)
                    && g[r as usize][c as usize].is_none()
                {
                    g[r as usize][c as usize] = Some(p);
                }
                c += 2;
            }
            r += 1;
        }
    }
}

fn add_texture(b: &[u8; 32], g: &mut Grid, type_idx: u8) {
    match type_idx {
        0 => {
            // person — bytes 22..32
            let mut br = BitReader::new(b, 22);
            tzones(
                &mut br,
                g,
                &[
                    [0, 0, 2, 5, 4],
                    [13, 0, 15, 5, 4],
                    [0, 10, 2, 15, 7],
                    [13, 10, 15, 15, 7],
                    [4, 0, 11, 2, 0],
                    [2, 3, 3, 8, 7],
                    [12, 3, 13, 8, 7],
                    [4, 8, 11, 11, 7],
                    [4, 12, 11, 15, 1],
                ],
            );
        }
        1 => {
            let mut br = BitReader::new(b, 11);
            tzones(
                &mut br,
                g,
                &[
                    [0, 0, 1, 8, 4],
                    [14, 0, 15, 8, 4],
                    [0, 9, 1, 15, 7],
                    [14, 9, 15, 15, 7],
                    [2, 0, 13, 1, 7],
                    [2, 14, 13, 15, 8],
                    [1, 3, 3, 10, 7],
                    [12, 3, 14, 10, 7],
                    [4, 2, 11, 4, 8],
                    [4, 5, 11, 7, 7],
                    [3, 8, 12, 10, 1],
                    [4, 10, 11, 13, 7],
                    [3, 13, 12, 15, 8],
                    [2, 9, 3, 13, 7],
                    [12, 9, 13, 13, 7],
                ],
            );
        }
        2 => {
            let mut br = BitReader::new(b, 11);
            tzones(
                &mut br,
                g,
                &[
                    [0, 0, 1, 8, 4],
                    [14, 0, 15, 8, 4],
                    [0, 9, 1, 15, 7],
                    [14, 9, 15, 15, 7],
                    [2, 0, 13, 1, 4],
                    [2, 14, 13, 15, 0],
                    [1, 2, 2, 12, 0],
                    [13, 2, 14, 12, 0],
                    [2, 3, 4, 12, 7],
                    [11, 3, 13, 12, 7],
                    [5, 0, 10, 4, 4],
                    [4, 5, 11, 9, 1],
                    [4, 9, 11, 13, 6],
                    [0, 13, 3, 15, 3],
                    [12, 13, 15, 15, 3],
                ],
            );
        }
        3 => {
            let mut br = BitReader::new(b, 11);
            tzones(
                &mut br,
                g,
                &[
                    [0, 0, 3, 4, 4],
                    [12, 0, 15, 4, 4],
                    [0, 11, 3, 15, 4],
                    [12, 11, 15, 15, 4],
                    [0, 5, 1, 10, 0],
                    [14, 5, 15, 10, 0],
                    [2, 0, 13, 1, 7],
                    [2, 14, 13, 15, 7],
                    [1, 2, 3, 9, 7],
                    [12, 2, 13, 9, 7],
                    [4, 2, 11, 6, 8],
                    [4, 7, 11, 11, 7],
                    [3, 11, 12, 14, 0],
                    [5, 0, 10, 2, 4],
                ],
            );
        }
        4 => {
            let mut br = BitReader::new(b, 10);
            tzones(
                &mut br,
                g,
                &[
                    [0, 0, 1, 7, 4],
                    [14, 0, 15, 7, 4],
                    [0, 8, 1, 15, 8],
                    [14, 8, 15, 15, 8],
                    [2, 0, 13, 1, 8],
                    [2, 14, 13, 15, 6],
                    [2, 2, 3, 7, 4],
                    [12, 2, 13, 7, 4],
                    [2, 8, 3, 13, 8],
                    [12, 8, 13, 13, 8],
                    [4, 2, 11, 5, 4],
                    [4, 6, 11, 8, 7],
                    [3, 9, 5, 14, 4],
                    [10, 9, 12, 14, 4],
                    [6, 9, 9, 14, 7],
                    [5, 14, 10, 15, 6],
                ],
            );
        }
        _ => {}
    }
}

// ── Render ──────────────────────────────────────────────────────────────
fn render_svg(b: &[u8; 32]) -> String {
    let pal = make_palette(b);
    let bg = make_bg(b);
    let type_idx = b[6] % 5;

    let mut g = new_grid();
    match type_idx {
        0 => gen_person(b, &mut g),
        1 => gen_animal(b, &mut g),
        2 => gen_plant(b, &mut g),
        3 => gen_monster(b, &mut g),
        _ => gen_robot(b, &mut g),
    }
    add_texture(b, &mut g, type_idx);

    // 8-char unique id for the clipPath, drawn from the seed itself so
    // multiple avatars on one page don't collide.
    let uid = hex::encode(&b[0..4]);

    let mut s = String::with_capacity(4096);
    s.push_str(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 16 16\" \
         width=\"200\" height=\"200\" style=\"image-rendering:pixelated\">",
    );
    s.push_str(&format!(
        "<defs><clipPath id=\"cp{uid}\"><rect width=\"16\" height=\"16\" rx=\"1.7\"/></clipPath></defs>"
    ));
    s.push_str(&format!("<g clip-path=\"url(#cp{uid})\">"));
    s.push_str(&format!("<rect width=\"16\" height=\"16\" fill=\"{bg}\"/>"));

    for r in 0..GS {
        for c in 0..GS {
            if let Some(v) = g[r][c] {
                s.push_str(&format!(
                    "<rect x=\"{c}\" y=\"{r}\" width=\"1\" height=\"1\" fill=\"{}\"/>",
                    pal[v as usize]
                ));
            }
        }
    }
    s.push_str("</g></svg>");
    s
}

/// Generate a deterministic 16×16 pixel-art avatar from a 32-byte seed
/// and return it as a `data:image/svg+xml;base64,…` URL.
pub fn seed_to_data_url(seed: &[u8; 32]) -> String {
    let svg = render_svg(seed);
    let b64 = base64::engine::general_purpose::STANDARD.encode(svg.as_bytes());
    format!("data:image/svg+xml;base64,{b64}")
}

/// Same algorithm as `seed_to_data_url` but returns the raw SVG bytes —
/// suitable for serving directly as `image/svg+xml` from an HTTP route.
pub fn seed_to_svg(seed: &[u8; 32]) -> String {
    render_svg(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_seed() {
        let seed = [42u8; 32];
        let a = seed_to_data_url(&seed);
        let b = seed_to_data_url(&seed);
        assert_eq!(a, b);
    }

    #[test]
    fn differs_across_seeds() {
        let a = seed_to_data_url(&[1u8; 32]);
        let b = seed_to_data_url(&[2u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn returns_data_url_with_svg() {
        let url = seed_to_data_url(&[0u8; 32]);
        assert!(url.starts_with("data:image/svg+xml;base64,"));
        let b64 = url.trim_start_matches("data:image/svg+xml;base64,");
        let bytes = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
        let svg = std::str::from_utf8(&bytes).unwrap();
        assert!(svg.starts_with("<svg"));
        assert!(svg.contains("viewBox=\"0 0 16 16\""));
        assert!(svg.contains("</svg>"));
    }

    #[test]
    fn covers_all_top_level_types() {
        // b[6] selects the type. Hit each branch.
        for type_byte in 0u8..5 {
            let mut seed = [0u8; 32];
            seed[6] = type_byte;
            let url = seed_to_data_url(&seed);
            assert!(url.starts_with("data:image/svg+xml;base64,"));
        }
    }

    /// Writes one sample SVG per top-level type to /tmp/avatars/ for
    /// manual visual inspection. Ignored by default; run with:
    ///   cargo test -p attestor-shared --lib avatar::tests::dump -- --ignored --nocapture
    #[test]
    #[ignore]
    fn dump_samples() {
        std::fs::create_dir_all("/tmp/avatars").unwrap();
        // 25 varied seeds — 5 per top-level type (b[6] forced) so every
        // category appears at least once, with sub-type/accessory variety
        // coming from b[7..].
        let seeds: Vec<[u8; 32]> = (0u8..25)
            .map(|i| {
                let mut s = [0u8; 32];
                for (k, b) in s.iter_mut().enumerate() {
                    *b = i.wrapping_mul(17).wrapping_add(k as u8).wrapping_mul(5);
                }
                s[6] = i % 5; // round-robin person/animal/plant/monster/robot
                s
            })
            .collect();
        for (i, seed) in seeds.iter().enumerate() {
            let svg = render_svg(seed);
            let path = format!("/tmp/avatars/sample_{i:02}.svg");
            std::fs::write(&path, &svg).unwrap();
            println!("wrote {path} type={} bytes={}", seed[6] % 5, svg.len());
        }
    }

    #[test]
    fn oklch_known_values() {
        // L=1, C=0 → white. Any hue collapses to white.
        let s = oklch_to_hex(1.0, 0.0, 0.0);
        assert_eq!(s, "#ffffff");
        // L=0, C=0 → black.
        let s = oklch_to_hex(0.0, 0.0, 0.0);
        assert_eq!(s, "#000000");
    }
}
