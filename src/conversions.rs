pub fn u32_to_u8(num: u32) -> [u8; 4] {
    let seg_1 = ((num & 0xff000000) >> 24) as u8;
    let seg_2 = ((num & 0xff0000) >> 16) as u8;
    let seg_3 = ((num & 0xff00) >> 8) as u8;
    let seg_4 = (num & 0xff) as u8;
    [seg_1, seg_2, seg_3, seg_4]
}

pub fn u8_slice_to_u32(nums: &[u8]) -> u32 {
    if nums.len() != 4 {
        panic!("Must have exactly 4 numbers to convert.")
    }
    ((nums[0] as u32) << 24)
    | ((nums[1] as u32) << 16)
    | ((nums[2] as u32) << 8)
    | (nums[3] as u32)
}

pub fn u16_to_u8(num: u16) -> [u8; 2] {
    let seg_1 = ((num & 0xff00) >> 8) as u8;
    let seg_2 = (num & 0xff) as u8;
    [seg_1, seg_2]
}

pub fn u8_to_u16(nums: [u8; 2]) -> u16 {
    ((nums[0] as u16) << 8) | (nums[1] as u16)
}

pub fn bool_to_u16(boolean: bool) -> u16 {
    match boolean {
        true => 1,
        false => 0
    }
}

pub fn u16_to_bool(num: u16) -> bool {
    match num {
        1 => true,
        0 => false,
        _ => panic!("Can only convert 0 or 1 to bool.")
    }
}

#[cfg(test)]
mod tests {
    use crate::conversions::*;
    #[test]
    fn u32_to_u8_test() {
        let num_1 = 0b11110000111100001111000011110000;
        let num_2 = 0b10101010101010101010101010101010;
        let num_3 = 0b11101100100000001110110010000000;
        assert_eq!(u32_to_u8(num_1), [0b11110000; 4]);
        assert_eq!(u32_to_u8(num_2), [0b10101010; 4]);
        assert_eq!(u32_to_u8(num_3), [0b11101100, 0b10000000, 0b11101100, 0b10000000]);
    }

    #[test]
    fn u8_to_u32_test() {
        let nums_1 = [0b11110000; 4];
        let nums_2 = [0b10101010; 4];
        let nums_3 = [0b11101100, 0b10000000, 0b11101100, 0b10000000];
        assert_eq!(u8_slice_to_u32(&nums_1), 0b11110000111100001111000011110000);
        assert_eq!(u8_slice_to_u32(&nums_2), 0b10101010101010101010101010101010);
        assert_eq!(u8_slice_to_u32(&nums_3), 0b11101100100000001110110010000000);
    }

    #[test]
    fn u16_to_u8_test() {
        let num_1 = 0b1111000011110000;
        let num_2 = 0b1010101010101010;
        let num_3 = 0b1110110010000000;
        assert_eq!(u16_to_u8(num_1), [0b11110000; 2]);
        assert_eq!(u16_to_u8(num_2), [0b10101010, 0b10101010]);
        assert_eq!(u16_to_u8(num_3), [0b11101100, 0b10000000]);
    }

    #[test]
    fn u8_to_u16_test() {
        let nums_1 = [0b11110000; 2];
        let nums_2 = [0b10101010, 0b10101010];
        let nums_3 = [0b11101100, 0b10000000];
        assert_eq!(u8_to_u16(nums_1), 0b1111000011110000);
        assert_eq!(u8_to_u16(nums_2), 0b1010101010101010);
        assert_eq!(u8_to_u16(nums_3), 0b1110110010000000);
    }

    #[test]
    fn bool_to_u16_test() {
        let val_true = true;
        let val_false = false;
        assert_eq!(bool_to_u16(val_true), 1);
        assert_eq!(bool_to_u16(val_false), 0);
    }

    #[test]
    #[should_panic]
    fn u16_to_bool_test() {
        let val_1 = 1;
        let val_0 = 0;
        assert_eq!(u16_to_bool(val_1), true);
        assert_eq!(u16_to_bool(val_0), false);
        // Testing panic! case of u16_to_bool
        let val_err = 673;
        u16_to_bool(val_err);
    }
}