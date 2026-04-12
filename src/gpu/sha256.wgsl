// SHA-256 compute shader
// Input: padded SHA-256 message as big-endian u32 words
// Output: 8 u32 words (digest, same integer values as big-endian spec)

struct Params {
    num_blocks: u32,
}

@group(0) @binding(0) var<storage, read>       msg:        array<u32>;
@group(0) @binding(1) var<storage, read_write> digest:     array<u32>;
@group(0) @binding(2) var<uniform>             params:     Params;
@group(0) @binding(3) var<storage, read>       init_state: array<u32>;

fn k_val(i: u32) -> u32 {
    switch i {
        case  0u: { return 0x428a2f98u; }
        case  1u: { return 0x71374491u; }
        case  2u: { return 0xb5c0fbcfu; }
        case  3u: { return 0xe9b5dba5u; }
        case  4u: { return 0x3956c25bu; }
        case  5u: { return 0x59f111f1u; }
        case  6u: { return 0x923f82a4u; }
        case  7u: { return 0xab1c5ed5u; }
        case  8u: { return 0xd807aa98u; }
        case  9u: { return 0x12835b01u; }
        case 10u: { return 0x243185beu; }
        case 11u: { return 0x550c7dc3u; }
        case 12u: { return 0x72be5d74u; }
        case 13u: { return 0x80deb1feu; }
        case 14u: { return 0x9bdc06a7u; }
        case 15u: { return 0xc19bf174u; }
        case 16u: { return 0xe49b69c1u; }
        case 17u: { return 0xefbe4786u; }
        case 18u: { return 0x0fc19dc6u; }
        case 19u: { return 0x240ca1ccu; }
        case 20u: { return 0x2de92c6fu; }
        case 21u: { return 0x4a7484aau; }
        case 22u: { return 0x5cb0a9dcu; }
        case 23u: { return 0x76f988dau; }
        case 24u: { return 0x983e5152u; }
        case 25u: { return 0xa831c66du; }
        case 26u: { return 0xb00327c8u; }
        case 27u: { return 0xbf597fc7u; }
        case 28u: { return 0xc6e00bf3u; }
        case 29u: { return 0xd5a79147u; }
        case 30u: { return 0x06ca6351u; }
        case 31u: { return 0x14292967u; }
        case 32u: { return 0x27b70a85u; }
        case 33u: { return 0x2e1b2138u; }
        case 34u: { return 0x4d2c6dfcu; }
        case 35u: { return 0x53380d13u; }
        case 36u: { return 0x650a7354u; }
        case 37u: { return 0x766a0abbu; }
        case 38u: { return 0x81c2c92eu; }
        case 39u: { return 0x92722c85u; }
        case 40u: { return 0xa2bfe8a1u; }
        case 41u: { return 0xa81a664bu; }
        case 42u: { return 0xc24b8b70u; }
        case 43u: { return 0xc76c51a3u; }
        case 44u: { return 0xd192e819u; }
        case 45u: { return 0xd6990624u; }
        case 46u: { return 0xf40e3585u; }
        case 47u: { return 0x106aa070u; }
        case 48u: { return 0x19a4c116u; }
        case 49u: { return 0x1e376c08u; }
        case 50u: { return 0x2748774cu; }
        case 51u: { return 0x34b0bcb5u; }
        case 52u: { return 0x391c0cb3u; }
        case 53u: { return 0x4ed8aa4au; }
        case 54u: { return 0x5b9cca4fu; }
        case 55u: { return 0x682e6ff3u; }
        case 56u: { return 0x748f82eeu; }
        case 57u: { return 0x78a5636fu; }
        case 58u: { return 0x84c87814u; }
        case 59u: { return 0x8cc70208u; }
        case 60u: { return 0x90befffau; }
        case 61u: { return 0xa4506cebu; }
        case 62u: { return 0xbef9a3f7u; }
        case 63u: { return 0xc67178f2u; }
        default:  { return 0u; }
    }
}

fn rotr(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }
fn ch(x: u32, y: u32, z: u32)  -> u32 { return (x & y) ^ (~x & z); }
fn maj(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (x & z) ^ (y & z); }
fn ep0(x: u32) -> u32 { return rotr(x, 2u)  ^ rotr(x, 13u) ^ rotr(x, 22u); }
fn ep1(x: u32) -> u32 { return rotr(x, 6u)  ^ rotr(x, 11u) ^ rotr(x, 25u); }
fn sig0(x: u32) -> u32 { return rotr(x, 7u) ^ rotr(x, 18u) ^ (x >> 3u); }
fn sig1(x: u32) -> u32 { return rotr(x, 17u) ^ rotr(x, 19u) ^ (x >> 10u); }

@compute @workgroup_size(1)
fn main() {
    var h0: u32 = init_state[0];
    var h1: u32 = init_state[1];
    var h2: u32 = init_state[2];
    var h3: u32 = init_state[3];
    var h4: u32 = init_state[4];
    var h5: u32 = init_state[5];
    var h6: u32 = init_state[6];
    var h7: u32 = init_state[7];

    for (var blk: u32 = 0u; blk < params.num_blocks; blk++) {
        let base: u32 = blk * 16u;

        var w: array<u32, 64>;
        for (var i: u32 = 0u; i < 16u; i++) {
            w[i] = msg[base + i];
        }
        for (var i: u32 = 16u; i < 64u; i++) {
            w[i] = sig1(w[i - 2u]) + w[i - 7u] + sig0(w[i - 15u]) + w[i - 16u];
        }

        var a: u32 = h0; var b: u32 = h1; var c: u32 = h2; var d: u32 = h3;
        var e: u32 = h4; var f: u32 = h5; var g: u32 = h6; var h: u32 = h7;

        for (var i: u32 = 0u; i < 64u; i++) {
            let t1: u32 = h + ep1(e) + ch(e, f, g) + k_val(i) + w[i];
            let t2: u32 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }

        h0 += a; h1 += b; h2 += c; h3 += d;
        h4 += e; h5 += f; h6 += g; h7 += h;
    }

    digest[0] = h0; digest[1] = h1; digest[2] = h2; digest[3] = h3;
    digest[4] = h4; digest[5] = h5; digest[6] = h6; digest[7] = h7;
}
