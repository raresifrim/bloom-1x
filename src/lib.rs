pub mod bloom;
pub mod bloom_counter;

#[cfg(test)]
mod tests {
    use crate::bloom::Bloom1X;
    use crate::bloom_counter::Bloom1Counter;

    #[test]
    fn filter_membership() {
        let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_set_u32(i) == 0);
        }

        //check filter for current members
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_u32(i) == 1);
        }

        //check next int outside filter
        assert!(bloom_filter.query_u32(u16::MAX as u32 + 1) == 0)
    }

    #[test]
    fn query_and_update() {
        let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_set_u32(i) == 0);
        }

        //check filter for current members
        let mut count = 0;
        for i in (u16::MAX as u32 + 1)..(2 * u16::MAX as u32) {
            let result= bloom_filter.query_u64_with_result(i as u64);
            count += result.and_result;
            bloom_filter.update_filter(&result);
            assert!(bloom_filter.query_u32(i) == 1);
        }

        println!("Number of false positives: {}", count);
    }

    #[test]
    fn false_positive_768kb_small() {
        let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_set_u32(i) == 0);
        }

        //check filter for next set of numbers
        let mut count = 0;
        for i in (u16::MAX as u32 + 1)..(2 * u16::MAX as u32) {
            count += bloom_filter.query_and_set_u32(i);
        }
        let k = 4.0;
        let m = 96.0 * u16::MAX as f64;
        let n = 2.0 * u16::MAX as f64;
        let p = f64::powf(1.0 - f64::exp(-k / (m / n)), k);

        println!(
            "False Positives in {} elements = {}",
            2 * u16::MAX as u32,
            count
        );
        println!(
            "False Positives rate = {}",
            count as f64 / (2.0 * u16::MAX as f64)
        );
        println!("Computed False Positive rate = {}", p);
    }

    #[test]
    fn false_positive_768kb_large() {
        let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        let mut count: usize = 0;
        for i in 0..1_000_000 {
            count += bloom_filter.query_and_set_u64(i + 0xDEADBEEF) as usize;
        }

        for i in 1_000_000..2_000_000 {
            count += bloom_filter.query_and_set_u64(i + 0xDEADBEEF) as usize;
        }
        let k = 4.0;
        let m = 96.0 * u16::MAX as f64;
        let n = 2000000.0;
        let p = f64::powf(1.0 - f64::exp(-k / (m / n)), k);

        println!("False Positives in {} elements = {}", 2000000, count);
        println!("False Positives rate = {}", count as f64 / 2000000.0);
        println!("Computed False Positive rate = {}", p);
    }

    #[test]
    fn false_positive_36kb_small() {
        let mut bloom_filter = Bloom1X::new(2, 1024, 32, 96);

        let mut count: usize = 0;
        //test with 4000 elements
        for i in 0..4000 {
            count += bloom_filter.query_and_set_u32(i) as usize;
        }

        //check filter for next set of numbers
        for i in 4000..8000 {
            count += bloom_filter.query_and_set_u32(i) as usize;
        }

        println!(
            "False Positives in {} elements = {}",
            2 * u16::MAX as u32,
            count
        );
        println!(
            "False Positives rate = {}",
            count as f64 / (2.0 * u16::MAX as f64)
        );

        bloom_filter.clear();

        let mut count: usize = 0;
        //test with 4000 elements
        for i in 0..4000 {
            count += bloom_filter.query_and_set_u64(i + 0xDEADBEEF) as usize;
        }

        //check filter for next set of numbers
        for i in 4000..8000 {
            count += bloom_filter.query_and_set_u64(i + 0xDEADBEEF) as usize;
        }

        println!(
            "False Positives 2 in {} elements = {}",
            2 * u16::MAX as u32,
            count
        );
        println!(
            "False Positives 2 rate = {}",
            count as f64 / (2.0 * u16::MAX as f64)
        );

        let k = 2.0;
        let m = 36.0 * 1024.0; //FPGA BRAM block
        let n = 4000.0;
        let p = f64::powf(1.0 - f64::exp(-k / (m / n)), k);
        println!("Computed False Positive rate = {}", p);
    }

    #[test]
    fn query_by_result() {
         let mut bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..10000 {
            let qr = bloom_filter.query_u64_with_result(i as u64);
            assert!(qr.and_result == 0);
            bloom_filter.update_filter(&qr);
            let result = bloom_filter.query_by_result(&qr);
            assert!(result == 1);
        }

    }

    #[test]
    fn search_bytes() {
         let bloom_filter = Bloom1X::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        for i in 0..10000 {
            let bytes = u64::to_le_bytes(i);
            let qr1 = bloom_filter.query_bytes_with_result(&bytes);
            let qr2 = bloom_filter.search_bytes(&bytes);
            assert!(qr1.bit_indexes == qr2.bit_indexes && qr1.row_index == qr2.row_index);
        }

    }

     #[test]
    fn query_and_update_counters() {
        let mut bloom_filter = Bloom1Counter::new(4, u16::MAX as usize + 1, 96, 96);

        //generate first 2^16 numbers
        //and increment counters once
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_inc_u32(i) == 0);
            let current_filter = bloom_filter.get_counters_u32(i);
            println!("Index {i} -> Counter Result: {:?}", current_filter);
            for k in 0..4{
                assert!(current_filter.counters[k] >= 1);
            }
        }

        //increment counters twice
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_inc_u32(i) == 1);
            let current_filter = bloom_filter.get_counters_u32(i);
            println!("Index {i} -> Counter Result: {:?}", current_filter);
            for k in 0..4{
                assert!(current_filter.counters[k] >= 2);
            }
        }

        //check counters again through different function
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_u32(i) == 1);
            let current_filter = bloom_filter.get_counters_u32(i);
            for k in 0..4{
                assert!(current_filter.counters[k] >= 2);
            }
        }

         //decrement counters once
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_dec_u32(i) == 1);
            let current_filter = bloom_filter.get_counters_u32(i);
            println!("Index {i} -> Counter Result: {:?}", current_filter);
        }

        //decrement counters twice
        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_and_dec_u32(i) == 1);
            let current_filter = bloom_filter.get_counters_u32(i);
            println!("Index {i} -> Counter Result: {:?}", current_filter);
            for k in 0..4{
                assert!(current_filter.counters[k] == 0);
            }
        }

        for i in 0..(u16::MAX as u32 + 1) {
            assert!(bloom_filter.query_u32(i) == 0);
        }
    }
}
