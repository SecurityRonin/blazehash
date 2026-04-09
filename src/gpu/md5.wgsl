// MD5 compute shader (little-endian)
// Input: padded MD5 message as little-endian u32 words
// Output: 4 u32 words (little-endian digest)

struct Params {
    num_blocks: u32,
}

@group(0) @binding(0) var<storage, read>       msg:    array<u32>;
@group(0) @binding(1) var<storage, read_write> digest: array<u32>;
@group(0) @binding(2) var<uniform>             params: Params;

fn rotl(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }
fn F(b: u32, c: u32, d: u32) -> u32 { return (b & c) | (~b & d); }
fn G(b: u32, c: u32, d: u32) -> u32 { return (b & d) | (c & ~d); }
fn H(b: u32, c: u32, d: u32) -> u32 { return b ^ c ^ d; }
fn I(b: u32, c: u32, d: u32) -> u32 { return c ^ (b | ~d); }

fn t_val(i: u32) -> u32 {
    switch i {
        case 0u: { return 0xd76aa478u; }
        case 1u: { return 0xe8c7b756u; }
        case 2u: { return 0x242070dbu; }
        case 3u: { return 0xc1bdceeeu; }
        case 4u: { return 0xf57c0fafu; }
        case 5u: { return 0x4787c62au; }
        case 6u: { return 0xa8304613u; }
        case 7u: { return 0xfd469501u; }
        case 8u: { return 0x698098d8u; }
        case 9u: { return 0x8b44f7afu; }
        case 10u: { return 0xffff5bb1u; }
        case 11u: { return 0x895cd7beu; }
        case 12u: { return 0x6b901122u; }
        case 13u: { return 0xfd987193u; }
        case 14u: { return 0xa679438eu; }
        case 15u: { return 0x49b40821u; }
        case 16u: { return 0xf61e2562u; }
        case 17u: { return 0xc040b340u; }
        case 18u: { return 0x265e5a51u; }
        case 19u: { return 0xe9b6c7aau; }
        case 20u: { return 0xd62f105du; }
        case 21u: { return 0x02441453u; }
        case 22u: { return 0xd8a1e681u; }
        case 23u: { return 0xe7d3fbc8u; }
        case 24u: { return 0x21e1cde6u; }
        case 25u: { return 0xc33707d6u; }
        case 26u: { return 0xf4d50d87u; }
        case 27u: { return 0x455a14edu; }
        case 28u: { return 0xa9e3e905u; }
        case 29u: { return 0xfcefa3f8u; }
        case 30u: { return 0x676f02d9u; }
        case 31u: { return 0x8d2a4c8au; }
        case 32u: { return 0xfffa3942u; }
        case 33u: { return 0x8771f681u; }
        case 34u: { return 0x6d9d6122u; }
        case 35u: { return 0xfde5380cu; }
        case 36u: { return 0xa4beea44u; }
        case 37u: { return 0x4bdecfa9u; }
        case 38u: { return 0xf6bb4b60u; }
        case 39u: { return 0xbebfbc70u; }
        case 40u: { return 0x289b7ec6u; }
        case 41u: { return 0xeaa127fau; }
        case 42u: { return 0xd4ef3085u; }
        case 43u: { return 0x04881d05u; }
        case 44u: { return 0xd9d4d039u; }
        case 45u: { return 0xe6db99e5u; }
        case 46u: { return 0x1fa27cf8u; }
        case 47u: { return 0xc4ac5665u; }
        case 48u: { return 0xf4292244u; }
        case 49u: { return 0x432aff97u; }
        case 50u: { return 0xab9423a7u; }
        case 51u: { return 0xfc93a039u; }
        case 52u: { return 0x655b59c3u; }
        case 53u: { return 0x8f0ccc92u; }
        case 54u: { return 0xffeff47du; }
        case 55u: { return 0x85845dd1u; }
        case 56u: { return 0x6fa87e4fu; }
        case 57u: { return 0xfe2ce6e0u; }
        case 58u: { return 0xa3014314u; }
        case 59u: { return 0x4e0811a1u; }
        case 60u: { return 0xf7537e82u; }
        case 61u: { return 0xbd3af235u; }
        case 62u: { return 0x2ad7d2bbu; }
        case 63u: { return 0xeb86d391u; }
        default: { return 0u; }
    }
}

fn s_val(i: u32) -> u32 {
    // Shift amounts derived from round (i % 4) — same pattern repeats every 4 steps per round
    // Round 1 (i < 16): 7,12,17,22
    // Round 2 (i < 32): 5,9,14,20
    // Round 3 (i < 48): 4,11,16,23
    // Round 4 (i < 64): 6,10,15,21
    let j = i % 4u;
    if i < 16u {
        switch j {
            case 0u: { return 7u; }
            case 1u: { return 12u; }
            case 2u: { return 17u; }
            default: { return 22u; }
        }
    } else if i < 32u {
        switch j {
            case 0u: { return 5u; }
            case 1u: { return 9u; }
            case 2u: { return 14u; }
            default: { return 20u; }
        }
    } else if i < 48u {
        switch j {
            case 0u: { return 4u; }
            case 1u: { return 11u; }
            case 2u: { return 16u; }
            default: { return 23u; }
        }
    } else {
        switch j {
            case 0u: { return 6u; }
            case 1u: { return 10u; }
            case 2u: { return 15u; }
            default: { return 21u; }
        }
    }
}

@compute @workgroup_size(1)
fn main() {
    var a0: u32 = 0x67452301u;
    var b0: u32 = 0xefcdab89u;
    var c0: u32 = 0x98badcfeu;
    var d0: u32 = 0x10325476u;

    for (var blk: u32 = 0u; blk < params.num_blocks; blk++) {
        let base: u32 = blk * 16u;

        var M: array<u32, 16>;
        for (var i: u32 = 0u; i < 16u; i++) {
            M[i] = msg[base + i];
        }

        var A: u32 = a0;
        var B: u32 = b0;
        var C: u32 = c0;
        var D: u32 = d0;

        for (var i: u32 = 0u; i < 64u; i++) {
            var f_val: u32;
            var g: u32;
            if i < 16u {
                f_val = F(B, C, D);
                g = i;
            } else if i < 32u {
                f_val = G(B, C, D);
                g = (5u * i + 1u) % 16u;
            } else if i < 48u {
                f_val = H(B, C, D);
                g = (3u * i + 5u) % 16u;
            } else {
                f_val = I(B, C, D);
                g = (7u * i) % 16u;
            }

            let temp: u32 = D;
            D = C;
            C = B;
            B = B + rotl(A + f_val + t_val(i) + M[g], s_val(i));
            A = temp;
        }

        a0 += A;
        b0 += B;
        c0 += C;
        d0 += D;
    }

    digest[0] = a0;
    digest[1] = b0;
    digest[2] = c0;
    digest[3] = d0;
}
